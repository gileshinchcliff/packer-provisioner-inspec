package main

import (
  "os"
  "io"
  "net"
  "fmt"
  "log"
  "sync"
  "bytes"
  "bufio"
  "errors"
  "strconv"
  "strings"
  "os/exec"
  "unicode"
  "io/ioutil"
  "crypto/rsa"
  "crypto/rand"
  "crypto/x509"
  "encoding/pem"
  "golang.org/x/crypto/ssh"
  "github.com/hashicorp/packer/packer"
  "github.com/hashicorp/packer/common"
  "github.com/hashicorp/packer/packer/plugin"
  "github.com/hashicorp/packer/helper/config"
  "github.com/hashicorp/packer/template/interpolate"
)

type userKey struct {
  ssh.PublicKey
  privKeyFile string
}

type signer struct {
  ssh.Signer
}

// UI struct is a concurrent-safe implementation of packer.Ui
type UI struct {
  sem chan int
  ui packer.Ui
}

// Config struct defines the structure of the provisioner's configuration
type Config struct {
  common.PackerConfig `mapstructure:",squash"`
  ctx interpolate.Context

  // The command to run inspec
  Command string `mapstructure:"command"`

  // The path of the profile to run
  Profile string `mapstructure:"profile"`

  // Extra arugments to pass to the inspec command
  ExtraArguments []string `mapstructure:"extra_arguments"`

  // SSH specifics
  User string `mapstructure:"user"`
  LocalPort string `mapstructure:"local_port"`
  SSHHostKeyFile string `mapstructure:"ssh_host_key_file"`
  SSHAuthorizedKeyFile string `mapstructure:"ssh_authorized_key_file"`
  SFTPCmd string `mapstructure:"sftp_command"`

  // Target for inspec
  target string
}

// InspecProvisioner defines the provisioner
type InspecProvisioner struct {
  config Config
  adapter *adapter
  done chan struct{}
}

// Prepare method is required for packer provisioners
func (p *InspecProvisioner) Prepare(raws ...interface{}) error {
  p.done = make(chan struct{})

  err := config.Decode(&p.config, &config.DecodeOpts {
    Interpolate: true,
    InterpolateContext: &p.config.ctx,
    InterpolateFilter: &interpolate.RenderFilter {
      Exclude: []string{},
    },
  }, raws...)
  if err != nil {
    return err
  }

  // Defaults
  if p.config.Command == "" {
    p.config.Command = "inspec exec"
  }

  var errs *packer.MultiError
  err = validateProfileDirectoryConfig(p.config.Profile)
  if err != nil {
    errs = packer.MultiErrorAppend(errs, err)
  }

  if len(p.config.SSHAuthorizedKeyFile) > 0 {
    err = validateFileConfig(p.config.SSHAuthorizedKeyFile, "ssh_authorized_key_file", true)
    if err != nil {
      errs = packer.MultiErrorAppend(errs, err)
    }
  }

  if len(p.config.SSHHostKeyFile) > 0 {
    err = validateFileConfig(p.config.SSHHostKeyFile, "ssh_host_key_file", true)
    if err != nil {
      errs = packer.MultiErrorAppend(errs, err)
    }
  }

  if len(p.config.LocalPort) > 0 {
    if _, err := strconv.ParseUint(p.config.LocalPort, 10, 16); err != nil {
      errs = packer.MultiErrorAppend(errs, fmt.Errorf("local_port: %s must be a valid port", p.config.LocalPort))
    }
  } else {
    p.config.LocalPort = "0"
  }

  if p.config.User == "" {
    p.config.User = os.Getenv("USER")
  }
  if p.config.User == "" {
    errs = packer.MultiErrorAppend(errs, fmt.Errorf("user: could not determine current user from environment"))
  }

  if errs != nil && len(errs.Errors) > 0 {
    return errs
  }

  return nil
}

// Provision method is required for packer provisioners
func (p *InspecProvisioner) Provision(ui packer.Ui, comm packer.Communicator) error {
  ui.Say("Provisioning with Inspec...")

  k, err := newUserKey(p.config.SSHAuthorizedKeyFile)
  if err != nil {
    return err
  }

  hostSigner, err := newSigner(p.config.SSHHostKeyFile)
  if len(k.privKeyFile)> 0 {
    defer os.Remove(k.privKeyFile)
  }

  keychecker := ssh.CertChecker {
    UserKeyFallback: func(conn ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
      if user := conn.User(); user != p.config.User {
        return nil, errors.New("authentication failed")
      }

      if !bytes.Equal(k.Marshal(), pubkey.Marshal()) {
        return nil, errors.New("authentication failed")
      }

      return nil, nil
    },
  }

  config := &ssh.ServerConfig {
    AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
      log.Printf("authentication attempt from %s to %s as %s using %s", conn.RemoteAddr(), conn.LocalAddr(), conn.User(), method)
    },
    PublicKeyCallback: keychecker.Authenticate,
  }

  config.AddHostKey(hostSigner)

  localListener, err := func() (net.Listener, error) {
    port, err := strconv.ParseUint(p.config.LocalPort, 10, 16)
    if err != nil {
      return nil, err
    }

    tries := 1
    if port != 0 {
      tries = 10
    }

    for i := 0; i < tries; i++ {
      l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
      port++
      if err != nil {
        ui.Say(err.Error())
        continue
      }
      _, p.config.LocalPort, err = net.SplitHostPort(l.Addr().String())
      if err != nil {
        ui.Say(err.Error())
        continue
      }
      return l, nil
    }
    return nil, errors.New("Error setting up SSH proxy connection")
  }()
  if err != nil {
    return err
  }

  ui = newUI(ui)
  p.adapter = newAdapter(p.done, localListener, config, p.config.SFTPCmd, ui, comm)

  defer func() {
    log.Print("Closing SSH proxy connection")
    close(p.done)
    p.adapter.Shutdown()
  }()

  go p.adapter.Serve()

  if err := p.executeInspec(ui, comm, k.privKeyFile); err != nil {
    return fmt.Errorf("Error executing Inspec: %s", err)
  }

  return nil
  return nil
}

// Cancel method is required for packer provisioners
func (p *InspecProvisioner) Cancel() {
  if p.done != nil {
    close(p.done)
  }
  if p.adapter != nil {
    p.adapter.Shutdown()
  }
  os.Exit(0)
}

func (p *InspecProvisioner) executeInspec(ui packer.Ui, comm packer.Communicator, privKeyFile string) error {
  args := []string{fmt.Sprintf("--profiles-path %s --target %s", p.config.Profile, p.config.target)}
  if len(privKeyFile) > 0 {
    args = append(args, "-i", privKeyFile)
  }

  cmd := exec.Command(p.config.Command, args...)

  stdout, err := cmd.StdoutPipe()
  if err != nil {
    return err
  }
  stderr, err := cmd.StderrPipe()
  if err != nil {
    return err
  }

  wg := sync.WaitGroup{}
  repeat := func(r io.ReadCloser) {
    reader := bufio.NewReader(r)
    for {
      line, err := reader.ReadString('\n')
      if line != "" {
        line = strings.TrimRightFunc(line, unicode.IsSpace)
        ui.Message(line)
      }
      if err != nil {
        if err == io.EOF {
          break
        } else {
          ui.Error(err.Error())
          break
        }
      }
    }
    wg.Done()
  }
  wg.Add(2)
  go repeat(stdout)
  go repeat(stderr)

  ui.Say(fmt.Sprintf("Executing Inspec: %s", strings.Join(cmd.Args, " ")))
  if err := cmd.Start(); err != nil {
    return err
  }
  wg.Wait()
  if err != nil {
    return fmt.Errorf("Non-zero exit status: %s", err)
  }

  return nil
}

// Ask wraps packer.Ui Ask in chan
func (ui *UI) Ask(s string) (string, error) {
  ui.sem <- 1
  ret, err := ui.ui.Ask(s)
  <- ui.sem

  return ret, err
}

// Error wraps packer.Ui Error in chan
func (ui *UI) Error(s string) {
  ui.sem <- 1
  ui.ui.Error(s)
  <- ui.sem
}

// Machine wraps packer.Ui Machine in chan
func (ui *UI) Machine(t string, args ...string) {
  ui.sem <- 1
  ui.ui.Machine(t, args...)
  <- ui.sem
}

// Message wraps packer.Ui Message in chan
func (ui *UI) Message(s string) {
  ui.sem <- 1
  ui.ui.Message(s)
  <- ui.sem
}

// Say wraps packer.Ui Say in chan
func (ui *UI) Say(s string) {
  ui.sem <- 1
  ui.ui.Say(s)
  <- ui.sem
}

func newSigner(privKeyFile string) (*signer, error) {
  signer := new(signer)

  if len(privKeyFile) > 0 {
    privateBytes, err := ioutil.ReadFile(privKeyFile)
    if err != nil {
      return nil, errors.New("Failed to load private host key")
    }

    signer.Signer, err = ssh.ParsePrivateKey(privateBytes)
    if err != nil {
      return nil, errors.New("Failed to parse private host key")
    }

    return signer, nil
  }

  key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    return nil, errors.New("Failed to generate server key pair")
  }

  signer.Signer, err = ssh.NewSignerFromKey(key)
  if err != nil {
    return nil, errors.New("Failed to extract private key from generated key pair")
  }

  return signer, nil
}

func newUserKey(pubKeyFile string) (*userKey, error) {
  userKey := new(userKey)
  if len(pubKeyFile) > 0 {
    pubKeyBytes, err := ioutil.ReadFile(pubKeyFile)
    if err != nil {
      return nil, errors.New("Failed to read public key")
    }
    userKey.PublicKey, _, _, _, err = ssh.ParseAuthorizedKey(pubKeyBytes)
    if err != nil {
      return nil, errors.New("Failed to parse authorized key")
    }

    return userKey, nil
  }

  key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    return nil, errors.New("Failed to generate key pair")
  }

  userKey.PublicKey, err = ssh.NewPublicKey(key.Public())
  if err != nil {
    return nil, errors.New("Failed to extract public key from generated key pair")
  }

  // To support Inspec calling back to us, we need to write this file down
  privateKeyDer := x509.MarshalPKCS1PrivateKey(key)
  privateKeyBlock := pem.Block{
    Type: "RSA PRIVATE KEY",
    Headers: nil,
    Bytes: privateKeyDer,
  }
  tf, err := ioutil.TempFile("", "inspec-key")
  if err != nil {
    return nil, errors.New("failed to create private key to tmp file")
  }
  _, err = tf.Write(pem.EncodeToMemory(&privateKeyBlock))
  if err != nil {
    return nil, errors.New("failed to write private key to tmp file")
  }
  
  err = tf.Close()
  if err != nil {
    return nil, errors.New("failed to close private key tmp file")
  }
  userKey.privKeyFile = tf.Name()

  return userKey, nil
}

func validateFileConfig(name string, config string, req bool) error {
  if req {
    if name == "" {
      return fmt.Errorf("%s must be specified", config)
    }
  }

  info, err := os.Stat(name)
  if err != nil {
    return fmt.Errorf("%s: %s is invalid: %s", config, name, err)
  } else if info.IsDir() {
    return fmt.Errorf("%s: %s must point to a file", config, name)
  }

  return nil
}

func validateProfileDirectoryConfig(name string) error {
  info, err := os.Stat(name)
  if err != nil {
    return fmt.Errorf("profile: %s is invalid: %s", name, err)
  } else if !info.IsDir() {
    return fmt.Errorf("profile: %s must point to a valid directory", name)
  }

  return nil
}

func newUI(ui packer.Ui) packer.Ui {
  return &UI{sem: make(chan int, 1), ui: ui}
}

func main() {
  server, err := plugin.Server()
  if err != nil {
    log.Fatal(err)
  }

  server.RegisterProvisioner(new(InspecProvisioner))
  server.Serve()
}
