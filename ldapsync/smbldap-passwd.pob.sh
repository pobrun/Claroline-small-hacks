#!/usr/bin/perl -w

#  This code was developped by Jerome Tournier (jtournier@gmail.com) and
#  contributors (their names can be found in the CONTRIBUTORS file).

#  This was first contributed by IDEALX (http://www.opentrust.com/)

#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
#  USA.

#  Purpose :
#       . ldap-unix passwd sync for SAMBA>2.2.2 + LDAP
#       . may also replace /bin/passwd

# untaint environment
$ENV{'PATH'}= '/bin:/usr/bin';
$ENV{'SHELL'}= '/bin/sh';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

use strict;
use FindBin;
use FindBin qw($RealBin);
use lib "$RealBin/";
use smbldap_tools;

use Crypt::SmbHash;
use Digest::MD5 qw(md5);
use Digest::SHA1 qw(sha1);
use MIME::Base64 qw(encode_base64);

# function declaration
sub make_hash;
sub make_salt;

my $user= undef;
my $oldpass= undef;

my $arg;
my $update_samba_passwd= 1;
my $update_unix_passwd= 1;
my $force_update_samba_passwd=0;
#-> add this lines
my $usr= 0;
my $pass;
my $pass2;
#-> untill here
foreach $arg (@ARGV) {
    if ( substr( $arg, 0, 1 ) eq '-' ) {
        if ( $arg eq '-h' || $arg eq '-?' || $arg eq '--help' ) {
            print_banner;
            print "Usage: $0 [options] [username]\n";
            print "  -h, -?, --help show this help message\n";
            print "  -s             update only samba password\n";
            print "  -u             update only UNIX password\n";
            print "  -B             must change Samba password at logon\n";
            exit (6);
        } elsif ($arg eq '-s') {
            $update_samba_passwd= 1; $update_unix_passwd= 0;
        } elsif ($arg eq '-u') {
            $update_samba_passwd= 0; $update_unix_passwd= 1;
        } elsif ($arg eq '-B') {
            $force_update_samba_passwd= 1;
        }
    } else {
        if ( $< != 0 ) {
            die "Only root can specify username\n";
        }
#-> change the script by adding this lines
        if ( $usr == 1 ){
          $pass = $arg;
          last;
        }
        if ( $usr == 0 ){
          $user= $arg;
          $usr= 1;
        }
#-> untill here
    }
}

if (!defined($user)) {
    $user = getpwuid($<);               # $user=$ENV{"USER"};
}

# check if $user variable is not tainted
# [TODO] create proper user mask
$user =~ /^([-\@\ \w.]+\$?)$/ and $user = $1 or
    die "$0: username '$user' is tainted\n";


my ($dn,$ldap_master);
# First, connecting to the directory
if ($< != 0) {
    # non-root user
    if (!defined($oldpass)) {
        # prompt for password
        print "Identity validation...\nenter your UNIX password: ";
        system "/bin/stty -echo" if (-t STDIN);
        chomp($oldpass=<STDIN>);
        system "/bin/stty echo" if (-t STDIN);
        print "\n";
        $config{masterDN}="uid=$user,$config{usersdn}";
        $config{masterPw}="$oldpass";
        $ldap_master=connect_ldap_master();
        $dn=$config{masterDN};
        if (!is_user_valid($user, $dn, $oldpass)) {
            print "Authentication failure\n";
            exit (10);
        }
    }
} else {
    # root user
    $ldap_master=connect_ldap_master();
    # test existence of user in LDAP
    my $dn_line;
    if (!defined($dn_line = get_user_dn($user))) {
        print "$0: user $user doesn't exist\n";
        exit (10);
    }
    $dn = get_dn_from_line($dn_line);
}

my $samba = is_samba_user($user);

# Printing verbose message
if ( $samba and $update_samba_passwd ) {
    if ( $update_unix_passwd ) {
        print "Changing UNIX and samba passwords for $user\n";
    } else {
        print "Changing samba password for $user\n";
    }
} else {
    if ( $update_unix_passwd ) {
        print "Changing UNIX password for $user\n";
    } else {
        die "Internal error";
    }
}

#-> remove the pass and pass2 variable declarations and add the IF condition
if ( $usr != 1){
# prompt for new password
  print "New password: ";
  system "/bin/stty -echo" if (-t STDIN);
  chomp($pass=<STDIN>);
  system "/bin/stty echo" if (-t STDIN);
  print "\n";

  print "Retype new password: ";
  system "/bin/stty -echo" if (-t STDIN);
  chomp($pass2=<STDIN>);
  system "/bin/stty echo" if (-t STDIN);
  print "\n";

  if ($pass ne $pass2) {
    print "New passwords don't match!\n";
    exit (10);
  }
#-> don't forget to close the curly bracket
}
#-> that's it. no more changes from here on


# Prepare '$hash_password' for 'userPassword'
my $hash_password;
# Generate password hash
if ($config{with_slappasswd}) {
    # checking if password is tainted: nothing is changed!!!!
    # essential for perl 5.8
    ($pass =~ /^(.*)$/ and $pass=$1) or
        die "$0: user password is tainted\n";

    # use slappasswd to generate hash
    if ( $config{hash_encrypt} eq "CRYPT" && defined($config{crypt_salt_format}) ) {
        open BUF, "-|" or
            exec "$config{slappasswd}",
            "-h","{$config{hash_encrypt}}",
            "-c","$config{crypt_salt_format}",
            "-s","$pass";
        $hash_password = <BUF>;
        close BUF;
    } else {
        open(BUF, "-|") or
            exec "$config{slappasswd}",
            "-h","{$config{hash_encrypt}}",
            "-s","$pass";
        $hash_password = <BUF>;
        close BUF;
    }
} else {
    # use perl libraries to generate hash
    $hash_password = make_hash($pass,$config{hash_encrypt},$config{crypt_salt_format});
}
# check if a hash was generated, otherwise die
defined($hash_password) or
    die "I cannot generate the proper hash!\n";
chomp($hash_password);

# First, connecting to the directory
if ($< != 0) {
    # if we are not root, we close the connection to re-open it as a normal user
    $ldap_master->unbind;
    $config{masterDN}="uid=$user,$config{usersdn}";
    $config{masterPw}="$oldpass";
    $ldap_master=connect_ldap_master();
}

# only modify smb passwords if smb user
if ( $samba and $update_samba_passwd ) {
    if (!$config{with_smbpasswd}) {
        # generate LanManager and NT clear text passwords
        my ($sambaLMPassword,$sambaNTPassword) = ntlmgen $pass;
        # the sambaPwdLastSet must be updating
        my $date=time;
        my @mods;
        push(@mods, 'sambaLMPassword' => $sambaLMPassword);
        push(@mods, 'sambaNTPassword' => $sambaNTPassword);
        push(@mods, 'sambaPwdLastSet' => $date);
        if (defined $config{defaultMaxPasswordAge}) {
            my $new_sambaPwdMustChange=$date+$config{defaultMaxPasswordAge}*24*60*60;
            push(@mods, 'sambaPwdMustChange' => $new_sambaPwdMustChange);
            if ($< ==0) {
                push(@mods, 'sambaAcctFlags' => '[U]');
            }
        }
        if ($force_update_samba_passwd == 1) {
                    # To force a user to change his password:
                    # . the attribut sambaPwdLastSet must be != 0
                    # . the attribut sambaAcctFlags must not match the 'X' flag
                    my $winmagic = 2147483647;
                    my $valacctflags = "[U]";
                    push(@mods, 'sambaPwdMustChange' => 0);
                    push(@mods, 'sambaPwdLastSet' => $winmagic);
                    push(@mods, 'sambaAcctFlags' => $valacctflags);
                }
        # Let's change nt/lm passwords
        my $modify = $ldap_master->modify ( "$dn",
                                            'replace' => { @mods }
                                            );
        $modify->code && warn "Failed to modify SMB password: ", $modify->error ;

    } else {
        if ($< != 0) {
            my $FILE="|$config{smbpasswd} -s >/dev/null";
            open (FILE, $FILE) || die "$!\n";
            print FILE <<EOF;
$oldpass
$pass
$pass
EOF
                ;
            close FILE;
        } else {
            open FILE,"|-" or
                exec "$config{smbpasswd}","$user","-s";
            local $SIG{PIPE} = sub {die "buffer pipe terminated" };
            print FILE <<EOF;
$pass
$pass
EOF
                ;
            close FILE;
        }
    }
}
# Update 'userPassword' field
if ( $update_unix_passwd ) {
    my $shadowLastChange=int(time()/86400);
    my $modify;
    if ($< != 0) {
        $modify = $ldap_master->modify ( "$dn",
                                            changes => [
                                                        replace => [userPassword => "$hash_password"],
                                                        replace => [shadowLastChange => "$shadowLastChange"]
                                                        ]
                                            );
    } else {
        $modify = $ldap_master->modify ( "$dn",
                                            changes => [
                                                        replace => [userPassword => "$hash_password"],
                                                        replace => [shadowLastChange => "$shadowLastChange"],
                                                        replace => [shadowMax => "$config{defaultMaxPasswordAge}"]
                                                        ]
                                            );
    }
    $modify->code && warn "Failed to modify UNIX password: ", $modify->error ;
}

# take down session
$ldap_master->unbind;

exit 0;

# Generates hash to be one of the following RFC 2307 schemes:
# CRYPT,  MD5,  SMD5,  SHA, SSHA,  and  CLEARTEXT
# SSHA is default
# '%s' is a default crypt_salt_format
# A substitute for slappasswd tool
sub make_hash
{
    my $hash_encrypt;
    my $crypt_salt_format;

    my $clear_pass=$_[0] or return undef;
    $hash_encrypt='{' . $_[1] . '}' or $hash_encrypt = "{SSHA}";
    $crypt_salt_format=$_[2] or $crypt_salt_format = '%s';

    my $hash_pass;
    if ($hash_encrypt eq "{CRYPT}" && defined($crypt_salt_format)) {
        # Generate CRYPT hash
        # for unix md5crypt $crypt_salt_format = '$1$%.8s'
        my $salt = sprintf($crypt_salt_format,make_salt());
        $hash_pass = "{CRYPT}" . crypt($clear_pass,$salt);

    } elsif ($hash_encrypt eq "{MD5}") {
        # Generate MD5 hash
        $hash_pass = "{MD5}" . encode_base64( md5($clear_pass),'' );

    } elsif ($hash_encrypt eq "{SMD5}") {
        # Generate SMD5 hash (MD5 with salt)
        my $salt = make_salt(4);
        $hash_pass = "{SMD5}" . encode_base64( md5($clear_pass . $salt) . $salt,'');

    } elsif ($hash_encrypt eq "{SHA}") {
        # Generate SHA1 hash
        $hash_pass = "{SHA}" . encode_base64( sha1($clear_pass),'' );

    } elsif ($hash_encrypt eq "{SSHA}") {
        # Generate SSHA hash (SHA1 with salt)
        my $salt = make_salt(4);
        $hash_pass = "{SSHA}" . encode_base64( sha1($clear_pass . $salt) . $salt,'' );

    } elsif ($hash_encrypt eq "{CLEARTEXT}") {
        $hash_pass=$clear_pass;

    } else {
        $hash_pass=undef;
    }
    return $hash_pass;
}

# Generates salt
# Similar to Crypt::Salt module from CPAN
sub make_salt
{
    my $length=32;
    $length = $_[0] if exists($_[0]);

    my @tab = ('.', '/', 0..9, 'A'..'Z', 'a'..'z');
    return join "",@tab[map {rand 64} (1..$length)];
}

# - The End
