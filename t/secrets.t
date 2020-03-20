#!perl
use strict;
use warnings;

use Expect;
use lib 't';
use helper;
use Cwd qw(abs_path);
use Test::Differences;
use Test::Deep;
use JSON::PP qw/decode_json/;

use lib 'lib';
use Genesis;
use Genesis::Top;

$ENV{NOCOLOR} = 1;

subtest 'secrets-v2.7.0' => sub {
	plan skip_all => 'skipping secrets tests because SKIP_SECRETS_TESTS was set'
		if $ENV{SKIP_SECRETS_TESTS};
	plan skip_all => 'secrets-v2.7.0 not selected test'
		if @ARGV && ! grep {$_ eq 'secrets-v2.7.0'} @ARGV;

	my $vault_target = vault_ok;
	bosh2_cli_ok;

	chdir workdir('genesis-2.7.0') or die;
	reprovision init => 'something', kit => 'secrets-2.7.0';

	my $env_name = 'c-azure-us1-dev';
	my $root_ca_path = '/secret/genesis-2.7.0/root_ca';
	my $secrets_mount = 'secret/genesis-2.7.0/deployments';
	my $secrets_path = 'dev/azure/us1';
	local $ENV{SAFE_TARGET} = $vault_target;
	runs_ok("safe x509 issue -A --name 'root_ca.genesisproject.io' $root_ca_path", "Can create a base root ca");

	my $cmd = Expect->new();
	$cmd->log_stdout($ENV{GENESIS_TRACE} ? 1 : 0);
	$cmd->spawn("genesis new $env_name --secrets-mount $secrets_mount --secrets-path /$secrets_path/ --root-ca-path $root_ca_path");

	expect_ok $cmd, [ "What is your base domain?", sub { $_[0]->send("demo.genesisproject.io\n"); }];
	expect_exit $cmd, 0, "genesis creates a new environment and auto-generates certificates";

	my ($pass,$rc,$out) = runs_ok("genesis lookup $env_name .");
	my $properties;
	lives_ok {$properties = decode_json($out)} "genesis lookup on environment returns parsable json";

	# Feature: Setting the root_ca_path, secrets_mount and secrets_path on genesis new
	$secrets_mount = "/$secrets_mount/";
	is $properties->{genesis}{root_ca_path},  $root_ca_path,  "environment correctly specifies root ca path";
	is $properties->{genesis}{secrets_mount}, $secrets_mount, "environment correctly specifies secrets mount";
	is $properties->{genesis}{secrets_path},  $secrets_path,  "environment correctly specifies secrets path";

	# Feature: Secrets mount and path in use
	# Feature: Specify CA signer
	# Feature: Specify certificate key usage
	my $v = "$secrets_mount$secrets_path";
	($pass, $rc, $out) = runs_ok("genesis check-secrets $env_name", "genesis check-secrets runs without error");
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $out, <<EOF, "genesis new correctly created secrets of the correcd type and location";
Parsing kit secrets descriptions ... done. - XXX seconds
Retrieving all existing secrets ... done. - XXX seconds

Checking 16 secrets for c-azure-us1-dev under path '/secret/genesis-2.7.0/deployments/dev/azure/us1/':
  [ 1/16] fixed/ca X509 certificate - CA, signed by '$root_ca_path' ... found.
  [ 2/16] fixed/server X509 certificate - signed by 'fixed/ca' ... found.
  [ 3/16] top-level/top X509 certificate - CA, signed by '$root_ca_path' ... found.
  [ 4/16] secondary/ca X509 certificate - CA, signed by 'top-level/top' ... found.
  [ 5/16] secondary/server X509 certificate - signed by 'secondary/ca' ... found.
  [ 6/16] top-level/server X509 certificate - signed by 'top-level/top' ... found.
  [ 7/16] openVPN/certs/root X509 certificate - CA, self-signed ... found.
  [ 8/16] openVPN/certs/server X509 certificate - signed by 'openVPN/certs/root' ... found.
  [ 9/16] passwords:alt random password - 32 bytes ... found.
  [10/16] passwords:permanent random password - 128 bytes, fixed ... found.
  [11/16] passwords:uncrypted random password - 1024 bytes ... found.
  [12/16] passwords:word random password - 64 bytes, fixed ... found.
  [13/16] rsa RSA public/private keypair - 4096 bits, fixed ... found.
  [14/16] rsa-default RSA public/private keypair - 2048 bits ... found.
  [15/16] ssh SSH public/private keypair - 1024 bits ... found.
  [16/16] ssh-default SSH public/private keypair - 2048 bits, fixed ... found.
Completed - Duration: XXX seconds [16 found/0 skipped/0 errors]

EOF

	# Feature: Validate secrets, including signer and key usage
	($pass, $rc, $out) = runs_ok("genesis check-secrets $env_name --validate", "genesis check-secrets --validate runs without error");
	#{ diag $ENV{HOME}; local $ENV{HOME} = '/Users/dbell'; use Pry; pry; }
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	$out =~ s/expires in (\d+) days \(([^\)]+)\)/expires in $1 days (<timestamp>)/g;
	$out =~ s/ca\.n\d{9}\./ca.n<random>./g;
	eq_or_diff $out, <<EOF, "genesis new correctly created secrets of the correcd type and location";
Parsing kit secrets descriptions ... done. - XXX seconds
Retrieving all existing secrets ... done. - XXX seconds

Checking 16 secrets for c-azure-us1-dev under path '/secret/genesis-2.7.0/deployments/dev/azure/us1/':
  [ 1/16] fixed/ca X509 certificate - CA, signed by '/secret/genesis-2.7.0/root_ca' ... found.
          [✔ ] CA Certificate
          [✔ ] Signed by /secret/genesis-2.7.0/root_ca
          [✔ ] Valid: expires in 1824 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'ca.n<random>.fixed'
          [✔ ] Subject Alt Names: ca.n<random>.fixed

  [ 2/16] fixed/server X509 certificate - signed by 'fixed/ca' ... found.
          [✔ ] Signed by fixed/ca
          [✔ ] Valid: expires in 89 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'a really long name with DNS: in it'
          [✔ ] Subject Alt Names: a really long name with DNS: in it

  [ 3/16] top-level/top X509 certificate - CA, signed by '/secret/genesis-2.7.0/root_ca' ... found.
          [✔ ] CA Certificate
          [✔ ] Signed by /secret/genesis-2.7.0/root_ca
          [✔ ] Valid: expires in 1824 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'ca.n<random>.top-level'
          [✔ ] Subject Alt Names: ca.n<random>.top-level

  [ 4/16] secondary/ca X509 certificate - CA, signed by 'top-level/top' ... found.
          [✔ ] CA Certificate
          [✔ ] Signed by top-level/top
          [✔ ] Valid: expires in 3649 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'secondary.ca'
          [✔ ] Subject Alt Names: secondary.ca

  [ 5/16] secondary/server X509 certificate - signed by 'secondary/ca' ... found.
          [✔ ] Signed by secondary/ca
          [✔ ] Valid: expires in 364 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'secondary.server'
          [✔ ] Subject Alt Names: secondary.server

  [ 6/16] top-level/server X509 certificate - signed by 'top-level/top' ... found.
          [✔ ] Signed by top-level/top
          [✔ ] Valid: expires in 179 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'server.example.com'
          [✔ ] Subject Alt Names: server.example.com, system.demo.genesisproject.io, *.server.example.com, *.system.demo.genesisproject.io, 10.10.10.10

  [ 7/16] openVPN/certs/root X509 certificate - CA, self-signed ... found.
          [✔ ] CA Certificate
          [✔ ] Self-Signed
          [✔ ] Valid: expires in 1824 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'ca.openvpn'
          [✔ ] Subject Alt Names: ca.openvpn

  [ 8/16] openVPN/certs/server X509 certificate - signed by 'openVPN/certs/root' ... found.
          [✔ ] Signed by openVPN/certs/root
          [✔ ] Valid: expires in 179 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'server.openvpn'
          [✔ ] Subject Alt Names: server.openvpn

  [ 9/16] passwords:alt random password - 32 bytes ... found.
          [✔ ] 32 characters
          [✔ ] Formatted as base64 in ':alt-base64'

  [10/16] passwords:permanent random password - 128 bytes, fixed ... found.
          [✔ ] 128 characters

  [11/16] passwords:uncrypted random password - 1024 bytes ... found.
          [✔ ] 1024 characters
          [✔ ] Formatted as bcrypt in ':crypted'

  [12/16] passwords:word random password - 64 bytes, fixed ... found.
          [✔ ] 64 characters
          [✔ ] Only uses characters '01'

  [13/16] rsa RSA public/private keypair - 4096 bits, fixed ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] 4096 bit
          [✔ ] Public/Private key agreement

  [14/16] rsa-default RSA public/private keypair - 2048 bits ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] 2048 bit
          [✔ ] Public/Private key agreement

  [15/16] ssh SSH public/private keypair - 1024 bits ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] Public/Private key Agreement
          [✔ ] 1024 bits

  [16/16] ssh-default SSH public/private keypair - 2048 bits, fixed ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] Public/Private key Agreement
          [✔ ] 2048 bits

Completed - Duration: XXX seconds [16 found/0 skipped/0 errors]

EOF

	# Feature: No --force on rotate
	($pass,$rc,$out) = run_fails "genesis rotate-secrets --force $env_name -y", "genesis fails when --force option is used on rotate-secrets";
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $out, <<'EOF', "genesis reports no force option on rotate-secrets";
--force option no longer valid. See `genesis rotate-secrets -h` for more details
EOF

  my $env = Genesis::Top->new('.')->load_env($env_name);
  my ($secrets_old, $err) = $env->vault->all_secrets_for($env);
  my @secret_paths = map {my $p = $_ ; map {[$p, $_]} keys %{$secrets_old->{$_}}} keys %$secrets_old;

	($pass,$rc,$out) = runs_ok "genesis rotate-secrets $env_name -y --filter '/(/ca\$|passwords:)/'", "can rotate certs according to filter";
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $out, <<'EOF', "genesis rotate-secrets reports rotated filtered secrets, but not fixed ones";
Parsing kit secrets descriptions ... done. - XXX seconds

Recreating 6 secrets for c-azure-us1-dev under path '/secret/genesis-2.7.0/deployments/dev/azure/us1/':
  [1/6] fixed/ca X509 certificate - CA, signed by '/secret/genesis-2.7.0/root_ca' ... skipped
  [2/6] secondary/ca X509 certificate - CA, signed by 'top-level/top' ... done.
  [3/6] passwords:alt random password - 32 bytes ... done.
  [4/6] passwords:permanent random password - 128 bytes, fixed ... skipped
  [5/6] passwords:uncrypted random password - 1024 bytes ... done.
  [6/6] passwords:word random password - 64 bytes, fixed ... skipped
Completed - Duration: XXX seconds [3 recreated/3 skipped/0 errors]

EOF

  my ($secrets_new, $err2) = $env->vault->all_secrets_for($env);
  my (@different);
  for my $secret_path (@secret_paths) {
    my ($path, $key) = @$secret_path;
    push @different, join(":", $path, $key) if ($secrets_old->{$path}{$key} ne $secrets_new->{$path}{$key});
  }
  my @expected = qw(
    secret/genesis-2.7.0/deployments/dev/azure/us1/secondary/ca:certificate
    secret/genesis-2.7.0/deployments/dev/azure/us1/secondary/ca:key
    secret/genesis-2.7.0/deployments/dev/azure/us1/secondary/ca:crl
    secret/genesis-2.7.0/deployments/dev/azure/us1/secondary/ca:serial
    secret/genesis-2.7.0/deployments/dev/azure/us1/secondary/ca:combined
    secret/genesis-2.7.0/deployments/dev/azure/us1/passwords:alt
    secret/genesis-2.7.0/deployments/dev/azure/us1/passwords:alt-base64
    secret/genesis-2.7.0/deployments/dev/azure/us1/passwords:uncrypted
    secret/genesis-2.7.0/deployments/dev/azure/us1/passwords:crypted
  );
  cmp_deeply(\@different, bag(@expected), "Only the expected secrets changed");

	($pass,$rc,$out) = run_fails "genesis check-secrets $env_name --validate", "rotation does not rotate certs signed by changed cas";
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
  $out =~ s/expires in (\d+) days \(([^\)]+)\)/expires in $1 days (<timestamp>)/g;
  $out =~ s/ca\.n\d{9}\./ca.n<random>./g;
	eq_or_diff $out, <<'EOF', "genesis add-secrets reports existing secrets";
Parsing kit secrets descriptions ... done. - XXX seconds
Retrieving all existing secrets ... done. - XXX seconds

Checking 16 secrets for c-azure-us1-dev under path '/secret/genesis-2.7.0/deployments/dev/azure/us1/':
  [ 1/16] fixed/ca X509 certificate - CA, signed by '/secret/genesis-2.7.0/root_ca' ... found.
          [✔ ] CA Certificate
          [✔ ] Signed by /secret/genesis-2.7.0/root_ca
          [✔ ] Valid: expires in 1824 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'ca.n<random>.fixed'
          [✔ ] Subject Alt Names: ca.n<random>.fixed

  [ 2/16] fixed/server X509 certificate - signed by 'fixed/ca' ... found.
          [✔ ] Signed by fixed/ca
          [✔ ] Valid: expires in 89 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'a really long name with DNS: in it'
          [✔ ] Subject Alt Names: a really long name with DNS: in it

  [ 3/16] top-level/top X509 certificate - CA, signed by '/secret/genesis-2.7.0/root_ca' ... found.
          [✔ ] CA Certificate
          [✔ ] Signed by /secret/genesis-2.7.0/root_ca
          [✔ ] Valid: expires in 1824 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'ca.n<random>.top-level'
          [✔ ] Subject Alt Names: ca.n<random>.top-level

  [ 4/16] secondary/ca X509 certificate - CA, signed by 'top-level/top' ... found.
          [✔ ] CA Certificate
          [✔ ] Signed by top-level/top
          [✔ ] Valid: expires in 3649 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'secondary.ca'
          [✔ ] Subject Alt Names: secondary.ca

  [ 5/16] secondary/server X509 certificate - signed by 'secondary/ca' ... failed!
          [✘ ] Signed by secondary/ca
          [✔ ] Valid: expires in 364 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'secondary.server'
          [✔ ] Subject Alt Names: secondary.server

  [ 6/16] top-level/server X509 certificate - signed by 'top-level/top' ... found.
          [✔ ] Signed by top-level/top
          [✔ ] Valid: expires in 179 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'server.example.com'
          [✔ ] Subject Alt Names: server.example.com, system.demo.genesisproject.io, *.server.example.com, *.system.demo.genesisproject.io, 10.10.10.10

  [ 7/16] openVPN/certs/root X509 certificate - CA, self-signed ... found.
          [✔ ] CA Certificate
          [✔ ] Self-Signed
          [✔ ] Valid: expires in 1824 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'ca.openvpn'
          [✔ ] Subject Alt Names: ca.openvpn

  [ 8/16] openVPN/certs/server X509 certificate - signed by 'openVPN/certs/root' ... found.
          [✔ ] Signed by openVPN/certs/root
          [✔ ] Valid: expires in 179 days (<timestamp>)
          [✔ ] Modulus Agreement
          [✔ ] Subject Name 'server.openvpn'
          [✔ ] Subject Alt Names: server.openvpn

  [ 9/16] passwords:alt random password - 32 bytes ... found.
          [✔ ] 32 characters
          [✔ ] Formatted as base64 in ':alt-base64'

  [10/16] passwords:permanent random password - 128 bytes, fixed ... found.
          [✔ ] 128 characters

  [11/16] passwords:uncrypted random password - 1024 bytes ... found.
          [✔ ] 1024 characters
          [✔ ] Formatted as bcrypt in ':crypted'

  [12/16] passwords:word random password - 64 bytes, fixed ... found.
          [✔ ] 64 characters
          [✔ ] Only uses characters '01'

  [13/16] rsa RSA public/private keypair - 4096 bits, fixed ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] 4096 bit
          [✔ ] Public/Private key agreement

  [14/16] rsa-default RSA public/private keypair - 2048 bits ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] 2048 bit
          [✔ ] Public/Private key agreement

  [15/16] ssh SSH public/private keypair - 1024 bits ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] Public/Private key Agreement
          [✔ ] 1024 bits

  [16/16] ssh-default SSH public/private keypair - 2048 bits, fixed ... found.
          [✔ ] Valid private key
          [✔ ] Valid public key
          [✔ ] Public/Private key Agreement
          [✔ ] 2048 bits

Failed - Duration: XXX seconds [15 found/0 skipped/1 errors]

EOF

=pod
	# Feature: Renew certificates - can renew fixed certificates
	# Feature: Renew certificates - can renew failed certificates
	# Feature: Renew certificates - prompt on renew certificates when interactive
	($pass,$rc,$out) = runs_ok "genesis rotate-secrets --renew $env_name -y", "No force option on rotate";
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $out, <<'EOF', "genesis add-secrets reports existing secrets";
EOF

	# Feature: Rotate failed certificates
	($pass,$rc,$out) = run_fails "genesis rotate-secrets --force $env_name -y", "No force option on rotate";
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $out, <<'EOF', "genesis add-secrets reports existing secrets";
EOF
	# Feature: Remove secrets
	# Feature: Remove secrets - can remove fixed secrets
	# Feature: Remove secrets - can remove failed secrets
	# Feature: Remove secrets - can remove all secrets
	($pass,$rc,$out) = run_fails "genesis remove-secrets $env_name -y", "No force option on rotate";
	$out =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $out, <<'EOF', "genesis add-secrets reports existing secrets";
EOF
	# Genesis 2.7.0 Feature: Prompt for overwrite/delete on rotate/remove
	# Genesis 2.7.0 Feature: Filters on add, rotate, check, and remove
	# - filter cannot be specified more than once
	#
=cut
}	;

subtest 'secrets' => sub {
	plan skip_all => 'skipping secrets tests because SKIP_SECRETS_TESTS was set'
		if $ENV{SKIP_SECRETS_TESTS};
	plan skip_all => 'secrets-base not selected test'
		if @ARGV && ! grep {$_ eq 'secrets-base'} @ARGV;

	my $vault_target = vault_ok;
	bosh2_cli_ok;
	chdir workdir('redis-deployments') or die;

	reprovision init => 'redis',
				kit => 'omega';

	diag "\rConnecting to the local vault (this may take a while)...";
	expects_ok "new-omega us-east-sandbox";
	system('safe tree');

	my $sec;
	my $v = "secret/us/east/sandbox/omega";

	my $rotated = [qw[
	  test/random:username
	  test/random:password
	  test/random:limited

	  test/ssh/strong:public
	  test/ssh/strong:private
	  test/ssh/strong:fingerprint

	  test/ssh/meh:public
	  test/ssh/meh:private
	  test/ssh/meh:fingerprint

	  test/ssh/weak:public
	  test/ssh/weak:private
	  test/ssh/weak:fingerprint

	  test/rsa/strong:public
	  test/rsa/strong:private

	  test/rsa/meh:public
	  test/rsa/meh:private

	  test/rsa/weak:public
	  test/rsa/weak:private

	  test/fmt/sha512/default:random
	  test/fmt/sha512/default:random-crypt-sha512

	  test/fmt/sha512/at:random
	  test/fmt/sha512/at:cryptonomicon

	  auth/cf/uaa:shared_secret
	]];

	my $removed = [qw[
	  test/random:username

	  test/rsa/strong:public
	  test/rsa/strong:private

	  test/fixed/ssh:public
	  test/fixed/ssh:private
	  test/fixed/ssh:fingerprint

	  test/fmt/sha512/default:random
	  test/fmt/sha512/default:random-crypt-sha512
	]];

	my $fixed = [qw[
	  test/fixed/random:username

	  test/fixed/ssh:public
	  test/fixed/ssh:private
	  test/fixed/ssh:fingerprint

	  test/fixed/rsa:public
	  test/fixed/rsa:private

	  auth/cf/uaa:fixed
	]];

	my %before;
	for (@$rotated, @$fixed) {
	  have_secret "$v/$_";
	  $before{$_} = secret "$v/$_";
	}
	no_secret "$v/auth/github/oauth:shared_secret",
	  "should not have secrets from inactive subkits";

	is length($before{'test/random:username'}), 32,
	  "random secret is generated with correct length";

	is length($before{'test/random:password'}), 109,
	  "random secret is generated with correct length";

	like secret("$v/test/random:limited"), qr/^[a-z]{16}$/, "It is possible to limit chars used for random credentials";

	runs_ok "genesis rotate-secrets us-east-sandbox --no-prompt";
	my %after;
	for (@$rotated, @$fixed) {
	  have_secret "$v/$_";
	  $after{$_} = secret "$v/$_";
	}

	for (@$rotated) {
	  isnt $before{$_}, $after{$_}, "$_ should be rotated";
	}
	for (@$fixed) {
	  is $before{$_}, $after{$_}, "$_ should not be rotated";
	}

	# Test that nothing is missing
	my ($pass,$rc,$msg) = runs_ok "genesis check-secrets us-east-sandbox --verbose";
	unlike $msg, qr/\.\.\. missing/, "No secrets should be missing";
	unlike $msg, qr/\.\.\. error/, "No secrets should be errored";
	matches $msg, qr/\.\.\. found/, "Found secrets should be reported";

	# Test only missing secrets are regenerated
	%before = %after;
	for (@$removed) {
	  runs_ok "safe delete -f $v/$_", "removed $v/$_  for testing";
	  no_secret "$v/$_", "$v/$_ should not exist";
	}
	($pass,$rc,$msg) = run_fails "genesis check-secrets us-east-sandbox", 1;
	$msg =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $msg, <<EOF, "Only deleted secrets are missing";
Parsing kit secrets descriptions ... done. - XXX seconds
Retrieving all existing secrets ... done. - XXX seconds

Checking 16 secrets for us-east-sandbox under path '/secret/us/east/sandbox/omega/':
  [ 1/16] auth/cf/uaa:fixed random password - 128 bytes, fixed ... found.
  [ 2/16] auth/cf/uaa:shared_secret random password - 128 bytes ... found.
  [ 3/16] test/fixed/random:username random password - 32 bytes, fixed ... found.
  [ 4/16] test/fmt/sha512/at:random random password - 8 bytes ... found.
  [ 5/16] test/fmt/sha512/default:random random password - 8 bytes ... missing!
  [ 6/16] test/random:limited random password - 16 bytes ... found.
  [ 7/16] test/random:password random password - 109 bytes ... found.
  [ 8/16] test/random:username random password - 32 bytes ... missing!
  [ 9/16] test/fixed/rsa RSA public/private keypair - 2048 bits, fixed ... found.
  [10/16] test/rsa/meh RSA public/private keypair - 2048 bits ... found.
  [11/16] test/rsa/strong RSA public/private keypair - 4096 bits ... missing!
  [12/16] test/rsa/weak RSA public/private keypair - 1024 bits ... found.
  [13/16] test/fixed/ssh SSH public/private keypair - 2048 bits, fixed ... missing!
  [14/16] test/ssh/meh SSH public/private keypair - 2048 bits ... found.
  [15/16] test/ssh/strong SSH public/private keypair - 4096 bits ... found.
  [16/16] test/ssh/weak SSH public/private keypair - 1024 bits ... found.
Failed - Duration: XXX seconds [12 found/0 skipped/4 errors]

EOF

	runs_ok "genesis add-secrets us-east-sandbox";
	for (@$rotated, @$fixed) {
	  have_secret "$v/$_";
	  $after{$_} = secret "$v/$_";
	}
	for my $path (@$rotated, @$fixed) {
	  if (grep {$_ eq $path} @$removed) {
		isnt $before{$path}, $after{$path}, "$path should be recreated with a new value";
	  } else {
		is $before{$path}, $after{$path}, "$path should be left unchanged";
	  }
	}

	reprovision kit => 'asksecrets';
	my $cmd = Expect->new();
	#$ENV{GENESIS_TRACE} = 'y';
	$cmd->log_stdout($ENV{GENESIS_TRACE} ? 1 : 0);
	$cmd->spawn("genesis new east-us-sandbox");
	$v = "secret/east/us/sandbox/asksecrets";
	expect_ok $cmd, ['password .*\[hidden\]:', sub { $_[0]->send("my-password\n");}];
	expect_ok $cmd, ['password .*\[confirm\]:',  sub { $_[0]->send("my-password\n");}];
	expect_ok $cmd, ["\\(Enter <CTRL-D> to end\\)", sub {
		$_[0]->send("this\nis\nmulti\nline\ndata\n\x4");
	}];
	expect_exit $cmd, 0, "New environment with prompted secret succeeded";
	#$ENV{GENESIS_TRACE} = '';
	system('safe tree');
	have_secret "$v/admin:password";
	is secret("$v/admin:password"), "my-password", "Admin password was stored properly";
	have_secret "$v/cert:pem";
	is secret("$v/cert:pem"), <<EOF, "Multi-line secret was stored properly";
this
is
multi
line
data
EOF

	reprovision kit => "certificates";

	$cmd = Expect->new();
	$cmd->log_stdout($ENV{GENESIS_TRACE} ? 1 : 0);
	$cmd->spawn("genesis new west-us-sandbox");
	$v = "secret/west/us/sandbox/certificates";
	expect_ok $cmd, [ "Generate all the certificates?", sub { $_[0]->send("yes\n"); }];
	expect_ok $cmd, [ "What is your base domain?", sub { $_[0]->send("cf.example.com\n"); }];
	expect_exit $cmd, 0, "genesis creates a new environment and auto-generates certificates";

	have_secret "$v/auto-generated-certs-a/ca:certificate";
	my $x509 = qx(safe get $v/auto-generated-certs-a/ca:certificate | openssl x509 -inform pem -text);
	like $x509, qr/Issuer: CN\s*=\s*ca\.n\d+\.auto-generated-certs-a/m, "CA cert is self-signed";
	like $x509, qr/Subject: CN\s*=\s*ca\.n\d+\.auto-generated-certs-a/m, "CA cert is self-signed";

	have_secret "$v/auto-generated-certs-a/server:certificate";
	$x509 = qx(safe get $v/auto-generated-certs-a/server:certificate | openssl x509 -inform pem -text);
	like $x509, qr/Issuer: CN\s*=\s*ca\.n\d+\.auto-generated-certs-a/m, "server cert is signed by the CA";
	like $x509, qr/Subject: CN\s*=\s*server\.example\.com/m, "server cert has correct CN";
	like $x509, qr/DNS:$_/m, "server cert has SAN for $_"
	  for qw/server\.example\.com \*\.server\.example\.com \*\.system\.cf\.example\.com/;
	like $x509, qr/IP Address:10\.10\.10\.10/m, "server cert has an IP SAN for 10.10.10.10";

	have_secret "$v/auto-generated-certs-a/server:key";
	like secret("$v/auto-generated-certs-a/server:key"), qr/----BEGIN RSA PRIVATE KEY----/,
		"server private key looks like an rsa private key";

	have_secret "$v/auto-generated-certs-b/ca:certificate";
	my $ca_a = secret "$v/auto-generated-certs-a/ca:certificate";
	my $ca_b = secret "$v/auto-generated-certs-b/ca:certificate";
	isnt $ca_a, $ca_b, "CA for auto-generated-certs-a is different from that for auto-generated-certs-b";

	have_secret "$v/auto-generated-certs-b/server:certificate";
	$x509 = qx(safe get $v/auto-generated-certs-b/server:certificate | openssl x509 -inform pem -text);
	like $x509, qr/Issuer: CN\s*=ca\.asdf\.com/m, "server B cert is signed by the CA from auto-generated-certs-b";

	$cmd = Expect->new();
	$cmd->log_stdout($ENV{GENESIS_TRACE} ? 1 : 0);
	$cmd->spawn("genesis new north-us-sandbox");
	$v = "secret/north/us/sandbox/certificates";
	expect_ok $cmd, [ "Generate all the certificates?", sub { $_[0]->send("no\n"); }];
	expect_ok $cmd, [ "What is your base domain?", sub { $_[0]->send("cf.example.com\n"); }];
	expect_exit $cmd, 0, "genesis creates a new environment and doesn't create new certificates from ignored submodules";
	no_secret "$v/auto-generated-certs-b/ca";
	no_secret "$v/auto-generated-certs-b/server";

	$v = "secret/west/us/sandbox/certificates";
	runs_ok "safe delete -Rf $v", "clean up certs for rotation testing";
	no_secret "$v/auto-generated-certs-a/ca:certificate";
	($pass,$rc,$msg) = run_fails "genesis check-secrets west-us-sandbox", 1;
	$msg =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $msg, <<'EOF', "Removed certs should be missing";
Parsing kit secrets descriptions ... done. - XXX seconds
Retrieving all existing secrets ... done. - XXX seconds

Checking 6 secrets for west-us-sandbox under path '/secret/west/us/sandbox/certificates/':
  [1/6] auto-generated-certs-a/ca X509 certificate - CA ... missing!
  [2/6] auto-generated-certs-a/server X509 certificate - signed by 'auto-generated-certs-a/ca' ... missing!
  [3/6] auto-generated-certs-b/ca X509 certificate - CA ... missing!
  [4/6] auto-generated-certs-b/server X509 certificate - signed by 'auto-generated-certs-b/ca' ... missing!
  [5/6] fixed/ca X509 certificate - CA ... missing!
  [6/6] fixed/server X509 certificate - signed by 'fixed/ca' ... missing!
Failed - Duration: XXX seconds [0 found/0 skipped/6 errors]

EOF
	runs_ok "genesis rotate-secrets west-us-sandbox -y", "genesis creates-secrets our certs";
	have_secret "$v/auto-generated-certs-a/server:certificate";
	my $cert = secret "$v/auto-generated-certs-a/server:certificate";
	have_secret "$v/auto-generated-certs-a/ca:certificate";
	my $ca = secret "$v/auto-generated-certs-a/ca:certificate";

	sub get_cert_validity {
		use Time::Piece;
		my ($info) = @_;
		my $pattern = "%b%n%d %H:%M:%S %Y";
		my @i = $info =~ qr/Not Before:\s(.*\s+\d{4})\s+([^\n\r]*)\s+Not After\s+:\s(.*\s+\d{4})\s+([^\n\r]*)/m;
		return undef unless $i[1] eq $i[3]; # ensure timezones are the same
		return (Time::Piece->strptime($i[2], $pattern) - Time::Piece->strptime($i[0], $pattern));
	}

	# Check correct TTL
	my $fixed_ca = qx(safe get $v/fixed/ca:certificate | openssl x509 -inform pem -text);
	is get_cert_validity($fixed_ca), (5*365*24*3600), "CA cert has a 5 year validity period";

	# Check CA alternative names and default TTL
	my $auto_b_ca = qx(safe get $v/auto-generated-certs-b/ca:certificate | openssl x509 -inform pem -text);
	like $auto_b_ca, qr/Issuer: CN\s*=\s*ca\.asdf\.com/m, "CA cert is self-signed";
	like $auto_b_ca, qr/Subject: CN\s*=\s*ca\.asdf\.com/m, "CA cert is self-signed";
	like $auto_b_ca, qr/Subject Alternative Name:\s+DNS:ca.asdf.com,\s+IP Address:127.1.2.3\s*$/sm,
	               "CA has correct Subject Alternative Names";

	is get_cert_validity($auto_b_ca), (10*365*24*3600), "CA cert has a default 10 year validity period";


	have_secret "$v/fixed/server:certificate";
	my $fixed_cert = secret "$v/fixed/server:certificate";

	runs_ok "genesis rotate-secrets west-us-sandbox -y", "genesis does secrets rotate the CA";
	have_secret "$v/auto-generated-certs-a/ca:certificate";
	my $new_ca = secret "$v/auto-generated-certs-a/ca:certificate";
	isnt $ca, $new_ca, "CA cert does change under normal secret rotation";

	have_secret "$v/fixed/server:certificate";
	my $new_fixed = secret "$v/fixed/server:certificate";
	is $fixed_cert, $new_fixed, "Fixed certificate doesn't change under normal secret rotation";


	$ca = secret "$v/auto-generated-certs-a/ca:certificate";
	$cert = secret "$v/auto-generated-certs-a/server:certificate";
	($pass,$rc,$msg) = runs_ok "genesis add-secrets west-us-sandbox", "genesis add-secrets doesn't rotate the CA";
	$msg =~ s/(Duration:|-) \d+ seconds/$1 XXX seconds/g;
	eq_or_diff $msg, <<'EOF', "genesis add-secrets reports existing secrets";
Parsing kit secrets descriptions ... done. - XXX seconds

Adding 6 secrets for west-us-sandbox under path '/secret/west/us/sandbox/certificates/':
  [1/6] auto-generated-certs-a/ca X509 certificate - CA ... exists!
  [2/6] auto-generated-certs-a/server X509 certificate - signed by 'auto-generated-certs-a/ca' ... exists!
  [3/6] auto-generated-certs-b/ca X509 certificate - CA ... exists!
  [4/6] auto-generated-certs-b/server X509 certificate - signed by 'auto-generated-certs-b/ca' ... exists!
  [5/6] fixed/ca X509 certificate - CA ... exists!
  [6/6] fixed/server X509 certificate - signed by 'fixed/ca' ... exists!
Completed - Duration: XXX seconds [0 added/6 skipped/0 errors]

EOF

	have_secret "$v/auto-generated-certs-a/ca:certificate";
	$new_ca = secret "$v/auto-generated-certs-a/ca:certificate";
	is $ca, $new_ca, "CA cert doesnt change under normal add secrets";

	have_secret "$v/auto-generated-certs-a/server:certificate";
	my $new_cert = secret "$v/auto-generated-certs-a/server:certificate";
	is $cert, $new_cert, "Certificates do not change if existing";

	runs_ok "genesis rotate-secrets -y west-us-sandbox", "genesis rotates-secrets all certs";
	have_secret "$v/auto-generated-certs-a/server:certificate";
	$new_cert = secret "$v/auto-generated-certs-a/server:certificate";
	isnt $cert, $new_cert, "Certificates are rotated normally";

	chdir $TOPDIR;
	teardown_vault;
};

done_testing;
