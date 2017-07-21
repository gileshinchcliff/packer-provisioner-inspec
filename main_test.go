package main

import (
  "os"
  "io"
  "fmt"
  "path"
  "testing"
  "io/ioutil"
  "crypto/rand"
  "github.com/hashicorp/packer/packer"
)

func testConfig(t *testing.T) map[string]interface{} {
  m := make(map[string]interface{})
  wd, err := os.Getwd()
  if err != nil {
    t.Fatalf("err: %s", err)
  }

  inspecStub := path.Join(wd, "packer-inspec-stub.sh")
  err = ioutil.WriteFile(inspecStub, []byte("#!/usr/bin/env bash\necho inspec 1.31.1"), 0777)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
  m["command"] = inspecStub

  return m
}

func createFile(filename string, t *testing.T) *os.File {
  tmp, err := ioutil.TempFile("", filename)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
  return tmp
}

func createDir(dirname string, t *testing.T) string {
  tmp, err := ioutil.TempDir("", dirname)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
  return tmp
}

func randomFile(t *testing.T) []byte {
  filename := make([]byte, 10)
  n, err := io.ReadFull(rand.Reader, filename)
  if n != len(filename) || err != nil {
    t.Fatalf("could not create random filename")
  }
  return filename
}
func TestImplementsInterface(t *testing.T) {
  var raw interface{}
  raw = &InspecProvisioner{}

  if _, ok := raw.(packer.Provisioner); !ok {
    t.Fatalf("InspecProvisioner is not a packer.Provisioner interface")
  }
}

func TestProvisionerPrepare_Defaults(t *testing.T) {
  var p InspecProvisioner
  config := testConfig(t)
  defer os.Remove(config["command"].(string))

  err := p.Prepare(config)
  if err == nil {
    t.Fatalf("should have error")
  }

  hostkeyFile := createFile("hostkey", t)
  defer os.Remove(hostkeyFile.Name())

  publickeyFile := createFile("publickey", t)
  defer os.Remove(publickeyFile.Name())

  profileDir := createDir("profile", t)
  defer os.Remove(profileDir)

  config["ssh_host_key_file"] = hostkeyFile.Name()
  config["ssh_authorized_key_file"] = publickeyFile.Name()
  config["profile"] = profileDir

  err = p.Prepare(config)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
}

func TestProvisionerPrepare_Profile(t *testing.T) {
  var p InspecProvisioner
  config := testConfig(t)
  defer os.Remove(config["command"].(string))

  hostkeyFile := createFile("hostkey", t)
  defer os.Remove(hostkeyFile.Name())

  publickeyFile := createFile("publickey", t)
  defer os.Remove(publickeyFile.Name())

  config["ssh_host_key_file"] = hostkeyFile.Name()
  config["ssh_authorized_key_file"] = publickeyFile.Name()
  config["profile"] = "doesnotexist"

  err := p.Prepare(config)
  if err == nil {
    t.Fatalf("should have error")
  }

  profileDir := createDir("profile", t)
  defer os.Remove(profileDir)
  config["profile"] = profileDir

  err = p.Prepare(config)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
}

func TestProvisionerPrepare_HostKeyFile(t *testing.T) {
  var p InspecProvisioner
  config := testConfig(t)
  defer os.Remove(config["command"].(string))

  publickeyFile := createFile("publickey", t)
  defer os.Remove(publickeyFile.Name())

  profileDir := createDir("profileDir", t)
  defer os.Remove(profileDir)

  hostkeyInvalid := randomFile(t)

  config["ssh_host_key_file"] = fmt.Sprintf("%x", hostkeyInvalid)
  config["ssh_authorized_key_file"] = publickeyFile.Name()
  config["profile"] = profileDir

  err := p.Prepare(config)
  if err == nil {
    t.Fatalf("should error if ssh_host_key_file does not exist")
  }

  hostkeyFile := createFile("hostkey", t)
  defer os.Remove(hostkeyFile.Name())
  config["ssh_host_key_file"] = hostkeyFile.Name()

  err = p.Prepare(config)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
}

func TestProvisionerPrepare_AuthorizedKeyFile(t *testing.T) {
  var p InspecProvisioner
  config := testConfig(t)
  defer os.Remove(config["command"].(string))

  hostkeyFile := createFile("hostkey", t)
  defer os.Remove(hostkeyFile.Name())

  profileDir := createDir("profile", t)
  defer os.Remove(profileDir)

  publickeyInvalid := randomFile(t)

  config["ssh_host_key_file"] = hostkeyFile.Name()
  config["ssh_authorized_key_file"] = fmt.Sprintf("%x", publickeyInvalid)
  config["profile"] = profileDir

  err := p.Prepare(config)
  if err == nil {
    t.Fatalf("should error if ssh_authorized_key_file does not exist")
  }

  publickeyFile := createFile("publickey", t)
  defer os.Remove(publickeyFile.Name())
  config["ssh_authorized_key_file"] = publickeyFile.Name()

  err = p.Prepare(config)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
}

func TestProvisionerPrepare_LocalPort(t *testing.T) {
  var p InspecProvisioner
  config := testConfig(t)
  defer os.Remove(config["command"].(string))

  hostkeyFile := createFile("hostkey", t)
  defer os.Remove(hostkeyFile.Name())

  publickeyFile := createFile("publickey", t)
  defer os.Remove(publickeyFile.Name())

  profileDir := createDir("profile", t)
  defer os.Remove(profileDir)

  config["ssh_host_key_file"] = hostkeyFile.Name()
  config["ssh_authorized_key_file"] = publickeyFile.Name()
  config["profile"] = profileDir
  config["local_port"] = "65537"

  err := p.Prepare(config)
  if err == nil {
    t.Fatalf("should error if local_port is invalid")
  }

  config["local_port"] = "22222"
  err = p.Prepare(config)
  if err != nil {
    t.Fatalf("err: %s", err)
  }
}
