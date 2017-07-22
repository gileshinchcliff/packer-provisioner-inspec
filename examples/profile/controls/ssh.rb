control 'ssh-is-running_1.0' do
  impact 1.0
  desc '
    This test ensures that ssh is running.
  '
  describe service('ssh') do
    it { should be_running }
  end
end
