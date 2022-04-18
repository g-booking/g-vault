package gVault;
use warnings;
use feature                    qw( signatures               );
no  warnings                   qw( experimental::signatures );
use Exporter;
use Syntax::Keyword::Try;
use Crypt::Mode::CBC;
use Crypt::PRNG                qw( rand random_bytes            );
use Crypt::Mac::BLAKE2b        qw( blake2b                      );
use Crypt::Digest::BLAKE2s_128 qw( blake2s_128                  );
use Crypt::Digest::BLAKE2b_256 qw( blake2b_256 blake2b_256_file );
use Crypt::Digest::BLAKE2b_512 qw( blake2b_512                  );
use Crypt::Digest::SHA3_512    qw( sha3_512                     );
use Crypt::Digest::Keccak512   qw( keccak512                    );
use Crypt::KeyDerivation       qw( hkdf_expand                  );
use Storable                   qw( freeze thaw                  );
use Data::Dump                 qw( dump                         );  
use Scalar::Util               qw( looks_like_number            );
use File::Basename;
use IO::Socket::UNIX;
use Cwd qw (realpath);

##use Carp qw (cluck);
use constant {
             GVAULT_FILE_SIZE   => 97360,
             GVAULT_CONF_SIZE   =>  1776,
             VERSION            => '0.90',
};
#require "/gbooking/g-booking-server/test/gcrypt/gPassword.pm";
  
    
my $MARK = 0;
my $SOCK_PATH = "/usr/local/_gvault/sock/.gvault.sock";
my  ( %save_env, %my_env, $config, $g_aes, $g_rc6, $g_ser, $g_two, $session_secret, $actual_secrets, $master_password, $pepper_gl, $pepper_secret, $json_hash, $netcat ); 

main();

sub main () {
  $g_aes                    = Crypt::Mode::CBC->new('AES',     1, 14);
  $g_rc6                    = Crypt::Mode::CBC->new('RC6',     1, 20);
  $g_ser                    = Crypt::Mode::CBC->new('Serpent', 1, 32);
  $g_two                    = Crypt::Mode::CBC->new('TwoFish', 1, 16);
  $session_secret->{secret} = random_bytes(32);
  $session_secret->{iv}     = random_bytes(16);
  capture_env();
  %save_env = %my_env;
}

sub capture_env {
  my %e = %ENV;
  foreach my $key  (grep { $_ =~/^_gv/ } keys %e) {
    $my_env{$key} = $ENV{$key};
  }
  $my_env{_gvid_} = session_enc($my_env{_gvid_}) if $my_env{_gvid_};
}

sub password_pepper ( $gvault ) {
  return session_dec (  $master_password->{$gvault}->{p2} ) if ( defined $master_password and $gvault and $master_password->{$gvault} );
  return;
}

sub ghash_256 ($gvault, $what)  {
  # a digest always get a 32 byte binary pepper from the gVault... so your HASHES are always unique regardless and they change from vault to vault... if you have more than one vault that is which probably you don't... but seemed reasonable to add in named vaults. stop waffling man.
  return blake2b_256 ( session_dec (  $master_password->{$gvault}->{p} ) . $what ) if ( defined $master_password and $gvault and $master_password->{$gvault} and $what );
  $gvault = $gvault || "undef";
  return _ERROR("Digest called but could not find the gVault [$gvault].");
  return;
}

sub ghash_512 ($gvault, $what)  {
  # a digest always get a 32 byte binary pepper from the gVault... so your HASHES are always unique regardless and they change from vault to vault... if you have more than one vault that is which probably you don't... but seemed reasonable to add in named vaults. stop waffling man.
  return blake2b_512 ( session_dec (  $master_password->{$gvault}->{p} ) . $what ) if ( defined $master_password and $gvault and $master_password->{$gvault} and $what );
  $gvault = $gvault || "undef";
  return _ERROR("Digest called but could not find the gVault [$gvault].");
  return;
}

sub save_secrets ($name_of_gvault, $gvault_file_name, $actual_secrets) {
  try {
    for (my $variation=0; $variation<=255; $variation++) {
      $actual_secrets->{$variation}->{s} = enc_aes ( ord(random_bytes(1)), $master_password->{$name_of_gvault}, session_dec( $actual_secrets->{$variation}->{s} ) );
      $actual_secrets->{$variation}->{v} = enc_aes ( ord(random_bytes(1)), $master_password->{$name_of_gvault}, session_dec( $actual_secrets->{$variation}->{v} ) );
      $actual_secrets->{$variation}->{h} = enc_aes ( ord(random_bytes(1)), $master_password->{$name_of_gvault}, session_dec( $actual_secrets->{$variation}->{h} ) );
      $actual_secrets->{$variation}->{k} = enc_aes ( ord(random_bytes(1)), $master_password->{$name_of_gvault}, session_dec( $actual_secrets->{$variation}->{k} ) );
    }
    for (my $variation=256; $variation<=319; $variation++) {
      $actual_secrets->{$variation}->{s} = enc_aes ( ord(random_bytes(1)), $master_password->{$name_of_gvault}, session_dec( $actual_secrets->{$variation}->{s} ) );
    }
    # Now we encrypt the entire thing with RC6 with an entirely new key...
    return save_file($gvault_file_name, enc_rc6 ( ord(random_bytes(1)), get_2nd_password($master_password->{$name_of_gvault}), freeze ($actual_secrets) ) );
  }
  catch  {
    _catch ($@);
    return _ERROR ("You messed something up man, could not save the file, make the secrets... something you are messing with...\n");
  }
}

sub save_file ($file_name, $what) {
  my $new_file = $file_name . "_" . time() . "_" . $$ . "_new_.g.tmp";
  if ( open(my $fh, '>', $new_file) ) {
    close $fh;
    chmod 0600, $new_file;
  }
  else {
    return _ERROR ("Could not open [$new_file] for writing, could not save... critical ditical man");
  }
  if ( open(my $fh, '>>', $new_file) ) {
    print $fh $what;
    close $fh;
    chmod 0400, $new_file;
  }
  else {
    close $fh if $fh; # ? probs not but hey
    unlink $new_file;
    return _ERROR ("Could not open [$new_file] for writing, could not save... critical ditical man");
  }
  ## and a final rename...  we do lock, sort of, in the "make_secrets" script.
  if ( rename $new_file, $file_name  ) {
    return 1;
  }
  else {
    return _ERROR ("Could not rename [$new_file] for [$file_name]... no save... critical ditical man");
  }
  return;
}

sub gload (@vault_names) {
  my $err = 1;
  my $master_load;
  foreach my $vault_load (@vault_names) {
    %my_env = %save_env;
    if ( $vault_load and not $actual_secrets->{$vault_load} ) {
      my $vault_secrets;
      $vault_secrets = load_vault($vault_load);

      if ( $vault_secrets and ref($vault_secrets) ne 'HASH' ) {
        $vault_load    = $vault_secrets;
        $vault_secrets = load_vault($vault_load);
      }

      if ( $vault_secrets and ref($vault_secrets) eq 'HASH' ) {
        ## Success... add secrets
        my ( $vault_name ) = get_vault_name ($vault_load);
        $actual_secrets->{$vault_name} = $vault_secrets;
      }
      else {
        _ERROR("The gvault [$vault_load] could not be loaded.");
        $err = 0;
      } 
    }
  }
  return $err;
}

sub gvault (@vault_names) {
  return gload(@vault_names);
}

sub get_vault_name ( $gvault ) {
  my ($gvault_name, $gvault_location) = get_gg($gvault);
  return $gvault_name;
}

sub get_gg ($gvault) {
  ## does it have .gvault at the end of it, and a "." at the start of it?... in which case it's a filename....
  if ( $gvault=~m/^.*?\.(.*?)\.gvault$/ ) {
    ## Passed a gvault file name...
    my $gname = $1;
    # let's check the name does not begin with a "." as it should not
    if ( $gname=~m/^.*?\.(.*?)$/ ) {
      $gname = $1;
    }
    return ($gname, $gvault) if -r $gvault and -f $gvault;
  }
  else {
    ## so must be a gvault name itself... so we will check HOME directory first... and then current directory.
    my $gvault_file = "\.$gvault.gvault";
    return ($gvault, $ENV{HOME} . "\/$gvault_file" ) if ( $ENV{HOME} and -r $ENV{HOME} . "\/$gvault_file" ); 
    return ($gvault, "./$gvault_file" ) if ( -r "./$gvault_file" ); 
  }
  return _ERROR("Have you generated the secrets for [$gvault] as I could not find or read them?  \n\n Please execute:\n       gvault -c $gvault\n\n") if $gvault_file and -r $gvault_file;
}

sub env ( $gvault ) {
  return if not $config->{1};
  return _ERROR("I don't have any config loaded.") if not $config->{1};
  return if not $config->{1};
  return "_gv_" . to_hex ( session_dec ( pepper_env ( $gvault, $config->{1} ) ) );
}

sub pepper_env ($gvault, $pepper) {
  return if not $pepper or not $config->{12};
  return session_enc( blake2s_128 ( blake2b_512($gvault) . $pepper . $config->{12} . $config->{13} ) );
}

sub get_etc_location ($file_name) {
  ## check if an etc exists... for this one... and a gVault.conf
  $file_name = realpath($file_name);

  my $dirname = dirname($file_name) if $file_name;
  return _ERROR ("I cannot find the gVault.conf for this vault.") if not $dirname;

 if ( $my_env{_gv_etc} ) {
    $file_name = $my_env{_gv_etc};
    delete $my_env{_gv_etc};
    return  $file_name;
  }

  if ( -r "$dirname/etc/gVault.conf" ) {
    # it does... let's load it in.
    $file_name = ("$dirname/etc/gVault.conf");
  }
  elsif  ( $ENV{HOME} and  -r $ENV{HOME} . '/etc/gVault.conf' ) {
    $file_name = ($ENV{HOME} . '/etc/gVault.conf');
  }
  elsif  ( -r '/etc/gVault.conf' ) {
    $file_name = ('/etc/gVault.conf');
  }
  else {
    return _ERROR ("I cannot find the gVault.conf for this vault.");
  }
  return $file_name;
}

sub load_json_conf_into_config {
  $config = load_json_conf($_[0]) or return _ERROR("error $_[0]");
}


sub load_vault {

  if ( not $my_env{_gvss_}  and $my_env{_gvid_} and  session_dec($my_env{_gvid_}) ) {
    my $id = blake2b_256 ( from_hex('d2cf868880618395e6f86a829377b5a9ad17a900') .  keccak512 (session_dec($my_env{_gvid_}) . " " . from_hex('fd531b53e20ed82e7475fde7')) );
    if ( 1 == 1 ) {
      my $secret_session = socket_send("SESSION pid=" .getppid() . " data=" . to_hex($id));
      if ( $secret_session ) {
        $my_env{_gvss_} = $secret_session;
      }
    }
  }
  my ( $etc_name, $name_of_gvault, $gvault_file_name );
  ( $name_of_gvault, $gvault_file_name ) = get_gg ($_[0]);
  return _ERROR("Could not establish gvault name from [$_[0]].") if not $name_of_gvault or not $gvault_file_name;

  my $gvault = $name_of_gvault;
  return _ERROR("I could not read the gVault [$name_of_gvault] from [$gvault].") if not -r $gvault_file_name;
  return _ERROR("gVault [$name_of_gvault] from [$gvault] has a bad length.")     if     -s $gvault_file_name != GVAULT_FILE_SIZE;

  # Now load the vault... and the config for that gvault...
  ## check if an etc exists... for this one... and a gVault.conf
  $etc_name = get_etc_location($gvault_file_name);

  return _ERROR ("I cannot find the gVault.conf for this vault.") if  not $etc_name;
  $config = load_json_conf($etc_name);
  my $gvault_data;
  if ( open (my $fh, '<', $gvault_file_name) ) {
    my $read_ok  = sysread ( $fh, $gvault_data,  -s $gvault_file_name );
    close $fh;
  }
  else {
    return _ERROR ("Secret gvault could not be opened [$gvault_file_name].");
  }
  return _ERROR ("Secret gvault failed to load, disk error, or something.. [$gvault_file_name].") if not $gvault_data or length($gvault_data) != GVAULT_FILE_SIZE;

  ## We definitely got the gVault encrypted data in the $gvault_data at this point... so now we need to decrypt it my man.
  ## Every gVault is encrypted with a different master key... so first we need to load the master key for this gvault...
  ## That master password is always stored in an ENV variable, well, at least in version 1 as I write this it is... I think it will stay like this
  ## as I will give other ways to effect this which are cryptographically secure as this makes all things simple... and cryptography is simple when you break it down
  ## ... it's just very hard to break down into it's super simple parts... and this is where people go wrong... this is where I hope I am not going wrong... but anyway
  ## stop waffling... what was I saying... so yer, we now check the ENV.... the ENV is part of a simple digest which is part of a the conf so it will change it something
  ## changes.. ok...woof..woof.
  
  my $tmp_secrets;

  my $loaded_master = load_master  ($master_password, $name_of_gvault, $gvault_file_name) or return; ##  _ERROR("Loading master failed.");
  if ( $loaded_master ) {
    if ( ref($loaded_master) eq 'HASH' ) {
      $master_password->{$gvault} = $loaded_master;
    }
    else {
      return $loaded_master;
    }
  }
  else {
    return;
  }

  ### decrypt gvault secrets now we have the master password for that vault............
  try {
    $tmp_secrets = thaw( dec_rc6 ( get_2nd_password($master_password->{$gvault}), $gvault_data ) );
    return _ERROR (" Secret gvault [$gvault_file_name] failed the HMAC check. Not loaded.") if not $tmp_secrets;
    return _ERROR("I could not LOAD gVault [$gvault] => [$gvault_file_name].") if not  $tmp_secrets->{0}->{s}; # if one fails, it's kaput man else all will work.
    for (my $variation=0; $variation<=255; $variation++) {
      $tmp_secrets->{$variation}->{s} = session_enc ( dec_aes ( $master_password->{$gvault}, ( $tmp_secrets->{$variation}->{s} ) ) );
      $tmp_secrets->{$variation}->{v} = session_enc ( dec_aes ( $master_password->{$gvault}, ( $tmp_secrets->{$variation}->{v} ) ) );
      $tmp_secrets->{$variation}->{h} = session_enc ( dec_aes ( $master_password->{$gvault}, ( $tmp_secrets->{$variation}->{h} ) ) );
      $tmp_secrets->{$variation}->{k} = session_enc ( dec_aes ( $master_password->{$gvault}, ( $tmp_secrets->{$variation}->{k} ) ) );
    }
    for (my $variation=256; $variation<=319; $variation++) {
      $tmp_secrets->{$variation}->{s} = session_enc ( dec_aes ( $master_password->{$gvault}, ( $tmp_secrets->{$variation}->{s} ) ) );
    }
  }
  catch  {
    _catch ($@);
    return _ERROR("I could not load gvault [$gvault] => [$gvault_file_name].\n");
  }
  return $tmp_secrets;
}

sub load_master ($tmp_master_password, $name_of_gvault, $gvault_file_name) {
  my $env;
  $env = env($name_of_gvault);

  if ( $env and $my_env{$env} ) {
    my $tmp_master_password_from_env_encrypted_with_pepper; 
    $tmp_master_password_from_env_encrypted_with_pepper = $my_env{$env};

    return _ERROR ("The master password for gVault [$name_of_gvault] is the wrong length [" . length($tmp_master_password_from_env_encrypted_with_pepper) . "] BUT EXISTS.  You may need to take manual action as the ENV exists but is wrong... are you messing around with me?") if  length ($tmp_master_password_from_env_encrypted_with_pepper) != 544;
    try { 
      if ( not make_master_secret($name_of_gvault) or not make_master_secret($name_of_gvault)->{s} or not make_master_secret($name_of_gvault)->{s2} or not make_master_secret($name_of_gvault)->{v} or not make_master_secret($name_of_gvault)->{v2} or not make_master_secret($name_of_gvault)->{h} or not make_master_secret($name_of_gvault)->{h2} ) {
        return _ERROR ("We need a pepper man, that's a blow out.");
      }
      # Let's make a quick test here... 
      return _ERROR ("Something is wrong with gVault master [$name_of_gvault], not loaded.") if not dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper));
      $tmp_master_password->{s}  = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)),  0,  32) );
      $tmp_master_password->{s2} = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 32,  32) );
      $tmp_master_password->{v}  = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 64,  16) );
      $tmp_master_password->{v2} = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 80,  16) );
      $tmp_master_password->{h}  = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 96,  16) );
      $tmp_master_password->{h2} = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 112, 16) );
      $tmp_master_password->{p}  = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 128, 32) );
      $tmp_master_password->{p2} = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 160, 32) );
      $tmp_master_password->{cc} = session_enc( substr(dec_aes_rc6 (make_master_secret($name_of_gvault), from_hex($tmp_master_password_from_env_encrypted_with_pepper)), 192, 32) );
      return if not $tmp_master_password;
      $master_password->{$name_of_gvault} = $tmp_master_password;
      return $tmp_master_password;
    }
    catch {
      _catch ($@);
      return _ERROR("I could not load the master password for the gvault [$name_of_gvault] -> [$gvault_file_name].");
    }
  }
  else {
    my $external_cmd = socket_send("EXTERNAL_CHECK");
    return if not $external_cmd;
    # External authorisation has given us some data... ok.
    my $cmd;
    try {
      $cmd->{_gv_}    = session_enc( thaw(from_hex($external_cmd))->{_gv_}    ); 
      $cmd->{_gv_id_} = session_enc( thaw(from_hex($external_cmd))->{_gv_id_} );
      $cmd->{gv_etc}  = session_enc( thaw(from_hex($external_cmd))->{gv_etc}  );
      $cmd->{gv_load} = session_enc( thaw(from_hex($external_cmd))->{gv_load} );
      $cmd->{master}  = session_enc( thaw(from_hex($external_cmd))->{master}  );
      $cmd->{gv_name} = session_enc( thaw(from_hex($external_cmd))->{gv_name} );
      $cmd->{env}     = session_enc( thaw(from_hex($external_cmd))->{env}     );
    }
    catch {
      undef $external_cmd;
      return _ERROR("g-Vault external authorisation has failed and this should not happen.");
    }
    undef $external_cmd;
    if ( $cmd ) {
      my $g_env        = session_dec($cmd->{env});
      $my_env{$g_env}  = session_dec($cmd->{master});
      $my_env{_gv_}    = session_dec( $cmd->{_gv_}    );
      $my_env{_gvid_}  = ( $cmd->{_gv_id_} ); # already encrypted
      $my_env{_gv_etc} = session_dec( $cmd->{gv_etc}  );
      return session_dec ( $cmd->{gv_load} ); 
    }
  }
  return  $tmp_master_password if  $tmp_master_password->{$name_of_gvault};
  _ERROR("The master password for the gvault [$name_of_gvault] could not be found or loaded. Please check your environment.") if  not  $tmp_master_password->{$name_of_gvault} ;
  return;
}

sub get_2nd_password ($pass) {
  my $p;
  $p->{s} =  $pass->{s2};
  $p->{v} =  $pass->{v2};
  $p->{h} =  $pass->{h2};
  return $p; 
}

sub session_dec {
  return _ERROR ("Nothing in session decrypt, this is likely a bug somewhere.") if not defined $_[0];
  $g_aes->decrypt ( $_[0], $session_secret->{secret}, $session_secret->{iv} )
}

sub session_enc {
  return if not defined $_[0];
  $g_aes->encrypt ( $_[0], $session_secret->{secret}, $session_secret->{iv} )
}
 
sub gdecrypt {
  my $secret;
  my $who    = $_[0];
  my $what   = $_[1];
     $secret = $_[2] if $_[2];
  return if not defined $what;
  my $algo   = ord(substr($what,0,1));
  if ( (not $secret)  and  ($actual_secrets->{$who}  ) ) {
    $secret = $actual_secrets->{$who}->{$algo};
  }
  else {
    $secret->{algo} = $algo;
  }

  $secret    = $actual_secrets->{$who}->{$algo} if (not $secret)  and  ($actual_secrets->{$who}  and  $actual_secrets->{$who}->{$algo});
  return _ERROR("The secret gvault [$who] could not be found.") if not $secret;

  if (     $secret->{algo} == 1 ) {
    return hkdf ( $secret, $master_password->{$who}->{cc} ), dec_aes( $secret, $what );
  }
  elsif (  $secret->{algo} == 2 ) {
    return hkdf ( $secret, $master_password->{$who}->{cc} ), dec_ser( $secret, $what );
  }
  elsif (  $secret->{algo} == 3 ) {
    return hkdf ( $secret, $master_password->{$who}->{cc} ), dec_two( $secret, $what );
  }
  elsif (  $secret->{algo} == 4 ) {
    return hkdf ( $secret, $master_password->{$who}->{cc} ), dec_rc6( $secret, $what );
  }
  return;
}

sub gencrypt {
  my $secret;
  my $who    = $_[0];
  return if not $who;
  my $what   = $_[1];
     $secret = $_[2] if $_[2];
  my $algo;
  if ( (not $secret)  and ($actual_secrets->{$who}  ) ) {
    $algo   = ord(random_bytes(1)); ## no need to orderly rotate... 
    $secret = $actual_secrets->{$who}->{$algo};
  }
  else {
    $algo   = $secret->{algo};
  }   
  return _ERROR("The secret gvault [$who] could not be found." ) if not $secret or not $secret->{algo};

  if (    $secret->{algo} == 1 ) {
    return hkdf( $secret, $master_password->{$who}->{cc} ), enc_aes ( $algo, $secret, $what );
  }
  elsif ( $secret->{algo} == 2 ) {
    return hkdf( $secret, $master_password->{$who}->{cc} ), enc_ser ( $algo, $secret, $what );
  }
  elsif ( $secret->{algo} == 3 ) {
    return hkdf( $secret, $master_password->{$who}->{cc} ), enc_two ( $algo, $secret, $what );
  }
  elsif ( $secret->{algo} == 4 ) {
    return hkdf( $secret, $master_password->{$who}->{cc} ), enc_rc6 ( $algo, $secret, $what );
  }
  return;
}

sub gpassword ( $gvault, $what ) {
  return if not $gvault or not $what;
  return if not looks_like_number($what);
  return if $what<256 or $what>319;

  if (  $actual_secrets->{$gvault}  ) {
    if (  $actual_secrets->{$gvault}->{$what}  ) {
      my $s = session_dec($actual_secrets->{$gvault}->{$what}->{s});
      return to_hex($s);
    }
  }
}
sub algo_info ($gvault, $what) {
  return if not $what or length($what) != 1;
  my $algo = ord($what);
  if (    $actual_secrets->{$gvault}->{$algo}->{algo} == 1 ) {
    return("AES", "14");
  }
  elsif (  $actual_secrets->{$gvault}->{$algo}->{algo} == 2 ) {
    return("SER", "32");
  }
  elsif (  $actual_secrets->{$gvault}->{$algo}->{algo} == 3 ) {
    return("TWO", "16");
  }
  elsif (  $actual_secrets->{$gvault}->{$algo}->{algo} == 4 ) {
    return("RC6", "20");
  }

}


sub info ( $gvault, $what ) {
  return if not defined $what or not defined $gvault;
  return _ERROR("The secret gvault [$gvault] could not be found.") if not $actual_secrets->{$gvault};
  return if not defined $what;
  my $algo = ord(substr($what,0,1));
  if (     $actual_secrets->{$gvault}->{$algo}->{algo} == 1 ) {
    return("gVault [$gvault] using secret [$algo] / 255 with [AES] algorithm, 14 rounds @ 384 bits of entropy.");
  }
  elsif (  $actual_secrets->{$gvault}->{$algo}->{algo} == 2 ) {
    return("gVault [$gvault] using secret [$algo] / 255 with [SERPENT] algorithm, 32 rounds @ 384 bits of entropy.");
  }
  elsif (  $actual_secrets->{$gvault}->{$algo}->{algo} == 3 ) {
    return("gVault [$gvault] using secret [$algo] / 255 with [TWO_FISH] algorithm, 16 rounds @ 384 bits of entropy.");
  }
  elsif (  $actual_secrets->{$gvault}->{$algo}->{algo} == 4 ) {
    return("gVault [$gvault] using secret [$algo] / 255 with [RC6] algorithm, 20 rounds @ 384 bits of entropy.");
  }
  return;
}

sub encrypt ( $who, $what ) {
  return gencrypt ($who, $what);
}
sub decrypt ( $who, $what ) {
  return gdecrypt ($who, $what);
}

sub hkdf ( $x, $master_salt ) {
  my $y;
  my $key    = hkdf_expand( session_dec($x->{k}), 'SHA256',  64, blake2b_512( session_dec($master_salt) ) . $x->{algo}        ); 
     $key    = session_enc( hkdf_expand( $key,    'SHA256', 128, blake2b_512( session_dec($x->{v}) . session_dec($x->{h}) ) ) );
  $y->{h}    = session_enc( substr(session_dec($key),  3, 32) );
  $y->{s}    = session_enc( substr(session_dec($key), 38, 32) );
  $y->{v}    = session_enc( substr(session_dec($key), 73, 16) );
  $y->{k}    = session_enc( substr(session_dec($key), 90, 32) );
  $y->{algo} = int(rand(4)) + 1; ## choose the next algo...
  return $y;
}

sub enc_aes ($algo, $x, $what) {
  try {
    my $encrypted  = $g_aes->encrypt ( (random_bytes(16) . $what), session_dec($x->{s}), session_dec($x->{v}) );
    return chr($algo) . blake2b ( 15, session_dec($x->{h}), $encrypted ) . $encrypted;  ##   1 is AES
  }
  catch  {
    _catch ($@);
    return _ERROR( $@ );
  }
}

sub enc_ser ($algo, $x, $what) {
  try {
    my $encrypted  = $g_ser->encrypt ( (random_bytes(16) . $what), session_dec($x->{s}), session_dec($x->{v}) );
    return chr($algo) . blake2b ( 15, session_dec($x->{h}), $encrypted ) . $encrypted;  ##   2 is SER 
  }
  catch  {
    _catch ($@);
    return _ERROR( $@ );
  }
}

sub enc_rc6 ($algo, $x, $what) {
  try {
    my $encrypted  = $g_rc6->encrypt ( (random_bytes(16) . $what), session_dec($x->{s}), session_dec($x->{v}) );
    my $hmac = blake2b ( 15, session_dec($x->{h}), $encrypted );
    return chr($algo) . blake2b ( 15, session_dec($x->{h}), $encrypted ) . $encrypted;  ##   4 is RC6 
  }
  catch  {
    _catch ($@);
    return _ERROR( $@ );
  }
}

sub enc_two ($algo, $x, $what) {
  try {
    my $encrypted  = $g_two->encrypt ( (random_bytes(16) . $what), session_dec($x->{s}), session_dec($x->{v}) );
    return chr($algo) . blake2b ( 15, session_dec($x->{h}), $encrypted ) . $encrypted;  ##   3 is TWO 
  }
  catch  {
    _catch ($@);
    return _ERROR( $@ );
  }
}

sub dec_two {
  my $h = blake2b( 15, session_dec($_[0]->{h}), substr($_[1], 16) );
  if ( $h ne substr($_[1],1,15) ) {
    return _ERROR ("HMAC check failure." ) if not $_[2];
    return;
  }
  return substr( $g_two->decrypt ( substr($_[1],16), session_dec($_[0]->{s}),  session_dec($_[0]->{v}) ), 16);
}

sub dec_ser ($x, $what) {
  return _ERROR ("HMAC check failure." ) if  blake2b( 15, session_dec($x->{h}), substr($what, 16) ) ne substr($what,1,15); ##HMAC
  return substr( $g_ser->decrypt ( substr($what,16), session_dec($x->{s}),  session_dec($x->{v}) ), 16);
}

sub dec_rc6 ($x, $what) {
  return _ERROR ("HMAC check failure." ) if blake2b( 15, session_dec($x->{h}), substr($what, 16) ) ne substr($what,1,15); ##HMAC
  return substr( $g_rc6->decrypt ( substr($what,16), session_dec($x->{s}),  session_dec($x->{v}) ), 16);
}

sub dec_aes ($x, $what) {
  return _ERROR ("HMAC check failure." ) if blake2b( 15, session_dec($x->{h}), substr($what, 16) ) ne substr($what,1,15); ##HMAC
  return substr( $g_aes->decrypt ( substr($what,16), session_dec($x->{s}),  session_dec($x->{v}) ), 16);
}
 
sub enc_aes_rc6 ($x, $what) {
  return if not defined $what;
  my $aes  = $g_aes->encrypt ( (random_bytes(8) . $g_rc6->encrypt ( (random_bytes(8) . $what), session_dec($x->{s2}), session_dec($x->{v2}) )),  session_dec($x->{s}),  session_dec($x->{v})  );
  return chr(int(rand(256))) . blake2b ( 15, session_dec($x->{h}) . session_dec($x->{h2}), $aes ) . $aes;
}

sub dec_aes_rc6($x, $what) {
  return _ERROR ("MASTER HMAC check failure.") if blake2b( 15, session_dec($x->{h}) . session_dec($x->{h2}), substr($what, 16) ) ne substr($what,1,15); ##HMAC
  my $aes  = $g_aes->decrypt ( substr($what,16), session_dec($x->{s}),  session_dec($x->{v}) );
  return substr($g_rc6->decrypt ( substr($aes,8), session_dec($x->{s2}),  session_dec($x->{v2}) ),8);
}

sub secret_sign ($name_of_gvault, $what) {
  ## Master key signage...
  return if not $what;
  return if not $master_password->{$name_of_gvault};
  if ( not $master_password->{$name_of_gvault}->{h2} ) {
    return blake2b ( 32, session_dec($master_password->{$name_of_gvault}->{h}), $what );
  }
  else {
    return blake2b ( 32, session_dec($master_password->{$name_of_gvault}->{h}) . session_dec($master_password->{$name_of_gvault}->{h2}), $what );
  }
}

sub check_secret_sign ($name_of_gvault, $what) {
  ## Master key signage...
  return if not $what or length($what)<35;
  return if not $master_password->{$name_of_gvault};
  my $sign_check = substr($what,0,32);
  $what          = substr($what,32);
  if ( not $master_password->{$name_of_gvault}->{h2} ) {
    my $hmac =  blake2b ( 32, session_dec($master_password->{$name_of_gvault}->{h}), $what );
    return 1 if $sign_check eq $hmac;
    return _ERROR ("HMAC failure for gvault [$name_of_gvault].");
    return;
  }
  else {
    try {
      my $hmac =  blake2b ( 32, session_dec($master_password->{$name_of_gvault}->{h}) . session_dec($master_password->{$name_of_gvault}->{h2}), $what );
      return 1 if $sign_check eq $hmac;
      return _ERROR ("HMAC failure for gvault [$name_of_gvault].");
    }
    catch {
      _catch ($@);
      return _ERROR("Big problems in China man.");
    }
  }
}

sub load_json_conf ($file_name) {
  $file_name=~s/^\/\//\//;
  my $json;
  $json = load_a_file( $file_name ) or return _ERROR("Could not load [$file_name].");
  if ( $json ) {
    ## thing is... when we make the .conf file which in turn makes the master and stuff then we don't have any real control over the autenticity of that
    ## so we bring this is here... it's a post operation... but that's ok... as hacking is also a post operation... you can't hack something that is not used.
    ## and frankly it really doesn't matter about this file but well we should at least give it some authenticity so if it ever is changed even a single bit
    ## then everything breaks... without this then we would not know that it actually had changed.... just stuff would start failing... ok... stop the waffle.
    $json_hash = blake2b_256 ($json);  # <= that's it really. We'll include it as part of our master password and then check it later.
    ## now it's encrypted.. it used to be json but well i dunno, i encrypted it with a joke password bcos why not, now we're all encrpyted everywhere but here is the password...
    ## we do a get a fixed length of course... and we interveave it with the master... so let's check the length....
    my $frozen_secret;
    return if not $my_env{_gvid_}; ### cron and some tasks don't have one so let's not complain
    #return _ERROR("Could not find your gVault ID.") if not $my_env{_gvid_};
    $frozen_secret = keccak512 ( from_hex('1563a4f6a701') . blake2b_256(session_dec($my_env{_gvid_}) . '*') . blake2b_256(from_hex('6c6c') . $file_name) );
    my $x;
    $x->{s} = gVault::session_enc( substr($frozen_secret,  0, 32) );
    $x->{v} = gVault::session_enc( substr($frozen_secret, 32, 16) );
    $x->{h} = gVault::session_enc( substr($frozen_secret, 48, 16) );

    try {
      ## we do HMAC check this file but not here... 
      my $jj =  gVault::dec_two($x, $json, 1);
      return thaw($jj) if $jj;
      return;
    }
    catch {
      _ERROR("Badboy...");
      return;
    }
  }
  return;
  return _ERROR("I could not load [$file_name], that's bad.");
}

# PEPPER the ENV MASTER with the below...


sub get_pid_data ($pid) {
  return if not looks_like_number($pid);
  if ( not -e "/proc/$pid" ) {
    _ERROR ("Cannot find the PID [$pid]........!!!!!!!!!!!!!!!!");
  }
  if ( my $data = load_a_file("/proc/$pid/stat") ) {
    my @pid_stat = split(/ /, $data, 23);
    my $data;
    if ( @pid_stat > 22 ) {
      $data->{uid}   = load_a_file("/proc/$pid/loginuid");
      $data->{cmd}   = load_a_file("/proc/$pid/cmdline");
      $data->{pid}   = $pid_stat[0];
      $data->{state} = $pid_stat[2];
      $data->{ppid}  = $pid_stat[3];
      $data->{tty}   = $pid_stat[6];
      $data->{start} = $pid_stat[21];
      return (keccak512( from_hex('ff6c0578f1a26bb0316d15c937610772bba99680b8f5e85d6aa6ebe5') . blake2b_256($pid_stat[0]).  blake2b_256($pid_stat[1]).  blake2b_256($pid_stat[3]).  blake2b_256($pid_stat[4]).  blake2b_256($pid_stat[5]).  blake2b_256($pid_stat[6]).  blake2b_256($pid_stat[7]).  blake2b_256($pid_stat[17]).  blake2b_256($pid_stat[18]).  blake2b_256($pid_stat[19]).  blake2b_256($pid_stat[21]) ), $data);
    }
  }
  return;
}

sub load_a_file ($file_name) {
  return if not $file_name;
  return _ERROR ("The file [$file_name] could not be read.") if not -r $file_name;
  my $file_data;
  if ( open (my $fh, '<', $file_name) ) {
    if ( my $read_ok  = sysread ( $fh, my $file_data,  2048 ) ) {
      close $fh;
      return $file_data;
    }
  }
  return _ERROR ("The file [$file_name] could not be read.") if not -r $file_name;
}

sub make_master_secret {
  my $gvault = $_[0] or return _ERROR("wtf?");
  my $u_hash = $json_hash;
     $u_hash = $_[1] if $_[1];
  return $pepper_secret->{$gvault} if $pepper_secret->{$gvault};
  my $p;
  $p->{s}  = pepper_32 ( $gvault, $config->{2} , $u_hash, $config->{19} );
  return if not $p->{s};
  $p->{s2} = pepper_32 ( $gvault, $config->{3} , $u_hash, $config->{20} );
  $p->{v}  = pepper_16 ( $gvault, $config->{4} , $u_hash, $config->{21} );
  $p->{v2} = pepper_16 ( $gvault, $config->{5} , $u_hash, $config->{22} );
  $p->{h}  = pepper_16 ( $gvault, $config->{6} , $u_hash, $config->{23} );
  $p->{h2} = pepper_16 ( $gvault, $config->{7} , $u_hash, $config->{24} );
  return _ERROR("wtf?") if not $p;
  $pepper_secret->{$gvault} = $p;
  return $pepper_secret->{$gvault};
}

sub config ($x) {
  return $config->{$x} if $config->{$x};
  return _ERROR("debil");
}

sub pepper_global_local ( $gvault_name, $u_local ) {
  ### so here is quite important really... as it's the only place that gVault allow user input....
  ### apart from here everything is automatic... so if you are trying to hack the algo, which I hope is not possible... anyway it's here...
  ### apart from here everything is randomly generated, 32 byte of binary, 16 bytes of IV.. different secrets for absolutely everything entirely... blah blah
  ### so here is the weakness....
  ### user input is always the weakness assuming it's not the idiot making use of cryptography and think they know what they are doing... i hope i am not an idiot.
  ### but must take care.

  # We allow 2 x types of over-ride with 2 x variations of when they apply.. something like...
  #    LOCAL  <login>         # entered once only at login
  #    GLOBAL <login>         
  #    LOCAL  <interactive>   # entered everytime...
  #    GLOVAL <interactive>

  # Now as much as I trust the latest not reverisble hashing algorithms then here we have an issue..
  # at this point we must imagine the entire system is compromised and worse than that the attacker is super amazing and is taking the time to read this and has made custom hack code.
  # HELLO!
  # So the MASTER PEPPER conf file is compromised and understood... so we cannot just rely on hashes here... well we could but from a crypto point of view
  # then this could introduce weakness that in theory could be exploited if not practically but this hacker is like super amazing god person with universe like cpu power.
  # so...

  # If there is "password input" then in theory it's already been ARGON'ed up... but the system allows for whatever so let's assume the user has bypassed that and
  # well there password is "password".... of course we will introduce a pepper regardless but the hacker sees this and does that himself too... therefore we gain nothing
  # over the god like person but gain a lot of any nomrmal person... but here is like god like...
  #
  # Overall, at this point, we cannot (we could) (but 4 speed) introduce another ARGON as well if bypassed then we need to accept that... and just trust the pepper... 
  # I think we need to introduce a TWOFISH here... this is super secure and I trust it, good old Bruce Boy, it's super slow which I like.
  # like well, you can determine that... so rather than just use DIGEST HASH'es then we will start from a TWOFISH encryption. 
  # We'll use a unique password and IV which we assume the attacker has compromised... but that's OK... the critical thing here is that they have
  # we do not weaken the crypto... if the user uses "password" as the secret and they have bypassed the ARGON and god person has understood everything and they have
  # compromised the entire system....   ENV variables...  /etc/conf  and the MASTER VAULT files... then well... probably it will take them <10 rounds to crack the algo...
  # that is fine... that is crypto... that is the situation... it's important to understand where you are at in crypto and then everything is dandy.
  # so here the ATTACKER will know the SECRET and IV and needs to get back to the PLAIN TEXT... so we encrypt.... and then digest... and then digest from that....
  # as opposed to digest of digest... as much as I trust the not reversible digest stuff which I don't in theory if I do in practise.
  # As we're using TWO FISH and then digest... then this process is basically irreversible based on any know possible contiumunm of anything that I understand..
  # What a waffler!!! JEEZ MAN!
  # So as long as the USER has used ARGON then this part remains hackable only via brute force... and that is why we introduce ArgonID here.
  #
  # So in the end what I mean is, the cryptographic integrity will be preserved but if you bypass the argon and your password is "password" and you are facing the super hacker
  # and everything has been entirely compromised and they are reading this and they have made the custom code... then well <10 goes... or just 1 if they try "password" first...
  # reality is the reality of the reality of the reality of the reality of the reality... ok, stop it... omg man, you could of finished the sub 20 mins ago!!
  # OK! 
  # We will TWOFISH the entire LOT all in one go... and for each one we will introduce a UNIQUE pepper...
  # And we will ARGON up the interactive data regardless.... elsewhere not here.
  # let's go g!

  return _ERROR("_gvid_ not set... looks like you're totally nuts to me.") if not $my_env{"_gvid_"};
  return _ERROR("We have a ulocal issue that shouldn't happen...you are messing? Try to resest all or something...") if not $u_local or length($u_local)<32;
  my $p_local = blake2b_256($gvault_name . $u_local);
  return $pepper_gl->{$p_local} if $pepper_gl->{$p_local};
  my $local_once   = $config->{8}; my $global_once  = $config->{9}; my $local_inter  = $config->{10}; my $global_inter = $config->{11}; my $global_id = $config->{17};
  $local_once     .= $my_env{"_gv_"  . $gvault_name . "_"}  if $my_env{"_gv_"  . $gvault_name . "_"};
  $local_inter    .= $my_env{"_gvi_" . $gvault_name . "_"}  if $my_env{"_gvi_" . $gvault_name . "_"};    
  $global_inter   .= $my_env{"_gvi_"}                       if $my_env{"_gvi_"};
  $global_id      .= blake2b_256 ( from_hex('cf88') .  keccak512 (session_dec($my_env{_gvid_}) . " " . from_hex('fd1b')) );

  # So, well assuming they cannot brute force the user input which they should not be able then we divert DIGEST here as like we divert TWO FISH here... the rest is the same.
  # Our final user_input..
  # If there is no user input then well, it's not difficult to crack if the entire system has been compromised.... so if there is user input then we want to make it as secure as possible.
  # so hopfully we do this here... and then we will use keccak later on....    with a blake digest....  
  try {
    $pepper_gl->{$p_local}  = session_enc ( sha3_512 ( g_two ( ($local_once . $global_once . session_dec(netcat($gvault_name)) . $local_inter . $global_inter . $config->{18} . $u_local . $global_id ), $config->{32}, $config->{16}  ) ) );
    return $pepper_gl->{$p_local};
  }
  catch {
    return;
  }
  return _ERROR("Could not encrypt the user input. This is like well bad.");
}



sub enc_data ($data)  {
  return if not $data;
  # A simple yet effective encryption between real-time UNIX sockets... uses real-time PID data + some pepper.
  my ($d, $p)= get_pid_data($$);
  my $hash = '';
  if ( $my_env{_gvss_}  and length($my_env{_gvss_}) == 128 ) {
    $d = keccak512  ( $d . from_hex(substr($my_env{_gvss_}, 64, 64)) );
  }
  else {
    $d = keccak512  ( $d );
  }

  my $secret = substr ($d,  9, 32);
  my $iv     = substr ($d, 47, 16);
  return $g_two->encrypt ( $_[0], $secret, $iv );
}


sub socket_send ($data) {
  my $client =  IO::Socket::UNIX->new(
      Type   => SOCK_STREAM(),
      Peer   => $SOCK_PATH,
  );
  if ( $client ) {
    if ( $my_env{_gvss_} ) {
      print $client "SES:" . substr($my_env{_gvss_},0,64) . to_hex(enc_data($data)) . "\n";
    }
    else {
      print $client "ENC:" . to_hex(enc_data($data)) . "\n";
    }
    $data = '';
    if ( $client ) {
      while (<$client>) {
        $data = $_;
      }
    }
    close $client;
    chomp $data;
    return $data;
  }
  return;
}

sub netcat {
  my $gvault_name = $_[0] if $_[0];
  return '' if not $my_env{_gvid_} or not $gvault_name;
  my $enc = session_enc ( $gvault_name . from_hex(session_dec($my_env{_gvid_}) ) );
  return $netcat->{$enc} if $netcat->{$enc};
    
  if ( not  $my_env{_gv_}  ) {
    $my_env{_gv_} = to_hex( sha3_512 ("warning, you have no interactive  $gvault_name" .  blake2b_256( session_dec($my_env{_gvid_}) . "x" ) . 'data' ) );
    _ERROR("WARNING: Interactive gVault data not found.");
    $netcat->{$enc} = session_enc ( sha3_512( 'z' . from_hex( blake2b_256(session_dec($my_env{_gvid_}) . $my_env{_gv_} ) ) ) );
    # removed this one -> delete $my_env{_gv_};
    return $netcat->{$enc} if $netcat->{$enc};
  }

  my $data;
  if (  substr( $my_env{_gv_},0,9 ) eq 'g_vaultd_' ) {
    try {
      my $client = IO::Socket::UNIX->new(
          Type => SOCK_STREAM(),
          Peer => $SOCK_PATH,
      );
      if ( not $client ) {
        if ( substr( $my_env{_gv_},0,9 ) eq 'g_vaultd_' ) {
          _ERROR ("This gVault was created with gVault daemon which is not running.");       
          return '';
        }
        $netcat->{$enc} = session_enc ( sha3_512( 'z' . from_hex( blake2b_256(session_dec($my_env{_gvid_}) . $my_env{_gv_} ) ) ) ); 
        # removed this one -> delete $my_env{_gv_};
        return $netcat->{$enc} if $netcat->{$enc};
      }
      if ( $my_env{_gvss_} ) {
        print $client "SES:" . substr($my_env{_gvss_},0,64) . to_hex(enc_data("GIVE gvid=" . session_dec($my_env{_gvid_}) . " data=$my_env{_gv_}")) . "\n";
      }
      else {
        print $client "ENC:" .                             to_hex(enc_data("GIVE gvid=" . session_dec($my_env{_gvid_}) . " data=$my_env{_gv_}")) . "\n";
      }
      $data = session_enc(from_hex(<$client>));
    }
    catch {
      return '';
    }
  }
  if (not $data) {
    if ( substr( $my_env{_gv_},0,9 ) eq 'g_vaultd_' ) {
      _ERROR("No data from the gVault daemon? You are not authenticated. Please re-authenticate by logging back in.");
      return '';
    }
    $netcat->{$enc} = session_enc( sha3_512( 'z' . from_hex( session_dec(blake2b_256($my_env{_gvid_})) . $my_env{_gv_} ) ) );
    # removed this one -> delete $my_env{_gv_};
    return $netcat->{$enc} if $netcat->{$enc};
  }
  $netcat->{$enc} = $data;
  # removed this one -> delete $my_env{_gv_};
  return $netcat->{$enc} if $netcat->{$enc};
  return '';
}

sub g_two ($w, $s, $i) {
  $g_two->encrypt ( $w, $s, $i )
}

sub pepper_16 ($gvault, $pepper, $u_hash, $u_local) {
  ## Could use MD5 here perfectly securely if we wanted as it might be broken but here, in this particular case, it's perfectly fine to use... but we don't just cos
  return _ERROR("You have a pepper_16 problem... it's blank..sort it out.. not good.") if not $pepper;
  return session_enc( blake2s_128 ( keccak512 ( $gvault . $pepper . $config->{12} . $config->{13} . session_dec(pepper_global_local($gvault, $u_local)) . $u_hash ) ) );
}

sub pepper_32 ($gvault, $pepper, $u_hash, $u_local) {
  return _ERROR("You have a pepper_32 problem... it's blank..sort it out.. not good.") if not $pepper;
  return if not pepper_global_local($gvault, $u_local);
  return session_enc( blake2b_256 ( keccak512 ( $gvault . $pepper . $config->{14} . $config->{15} . session_dec(pepper_global_local($gvault, $u_local))  . $u_hash) ) );
}

sub to_hex {
  return unpack("H*",  $_[0]) if $_[0];
  return;
}

sub from_hex {
  return pack 'H*', $_[0] if $_[0];
  return;
}

sub digest_file ($file_name) {
  if  ( -e $file_name  and  -r $file_name ) {
    return blake2b_256_file($file_name);
  }
  return "*" x 32;
}


sub check_permissions ($file_name) {
  if ( -e $file_name ) {
    my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size, $atime,$mtime,$ctime,$blksize,$blocks) = stat($file_name);
    return 1 if ( $nlink == 1  and  ($mode == 33024 or $mode == 32768) and $rdev == 0 );
  }
  die "The file permissions on [$file_name] are incorrect. No links. Owner read/write only. No funny business.\nPlease execute:\n   chmod 600 $file_name\nand re-run.\n";
}

sub _ERROR ($message) {
  chomp $message;
  print STDERR $message . "\n";
  return;
}

sub _INFO ($message) {
  chomp $message;
  print $message . "\n";
}

sub _catch($err_catch) {
  _ERROR ("********************************************************************************************\nCaught => $err_catch********************************************************************************************");
}

our @ISA       = qw( Exporter );
our @EXPORT_OK = qw( get_vault_name ghash_256 gvault gencrypt gdecrypt to_hex from_hex ghash_256 ghash_512 gload );

1;
