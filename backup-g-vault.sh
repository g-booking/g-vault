#!/usr/local/_gvault/bin/perl
use strict;
use Crypt::Argon2 qw/argon2id_pass argon2id_raw/;
use Term::ReadKey;
use Digest::SHA qw(sha512_hex);
ReadMode 4; # Turn off controls keys

print "g-Vault Backup:\n";
print " Here, we're going to back you up in a different way to any normal backup... you will create an encrypted backup of your g-Vaults....\n";
print "   and that encryption will be defined by a series of questions which you must answer honestly or in a way that you will always answer the same...\n";
print "Then, we run a high power ARGON ALGO on your answers so that it takes around 20 minutes to determine the HASH of your answers....\n";
print "  Therefore, any attack whom manages to infiltrate the secret which will be given to you in this process, must run the same... so they have no chance...\n";
print " AND... importantly... people lose passwords because they make them too clever... DO NOT BE CLEVER HERE... You are PROTECTED against brute force....\n";
print "    SO... you can be quite stupid... you can be honest.... a password of 'password' is no longer insecure although also don't be donkey...\n";
print "\nThis isn't designed to be nice so if you mess it up then CTRL-C and start again.... \n\nLastly, ** CASE MATTERS ** here!!! \n\n";

$| = 1; ## No buffering...

print "Do you prefer [t]ea  or  [c]offee      ?";
my $tea_coffee = ReadKey(0);
print "  [$tea_coffee]  \n";

print "Glass of [w]ine, bottle of [b]eer, or just [n]on-alcholic ?";
my $wine = ReadKey(0);
print "  [$wine]  \n";

print "Do you prefer a [s]hower  or a [b]ath  ?";
my $shower = ReadKey(0);
print "  [$shower]  \n";

print "Are you a [m]orning person or an [e]vening person?";
my $morning = ReadKey(0);
print "  [$morning]  \n";

print "Do you prefer a [q]uiet night in or a [n]ight on the town?";
my $night = ReadKey(0);
print "  [$night]  \n";
print "\nEnter any number you will always remember, it could be an ATM PIN you've always used as it won't be stored, it will only form part of the HASH....\n";
print "It could be your first kids birthday, it could be the anything in the world BUT it must be a number that you will always always remember when asked!\n";
print "   My number is : ";
ReadMode 0;
my $number = <STDIN>;
chomp $number;

print "\nEnter any word.... it can even be 'password' but something else would be better...you must always remember this word.... CASE SENSITIVE!!\n";
print "     My word is : ";
my $word = <STDIN>;
chomp $word;

print "\nEnter your birthday in the format dd/mm/yyyy! It should be your *real* birthday... it means the bad actor must know your birthday to access your backup...!\n";
print "DON'T try to be CLEVER, and add +1 to your day or month or year... or something.... as when you need to use this BACKUP you won't remember your clever move!!\n";
print " My birthday is : ";
my $bday = <STDIN>;
chomp $bday;

print "\nFinally, enter a film, or a book, or a TV show or a song that *pops* into your mind and that you would always remember...for your own personal reason...\n";
print "My no.1 media is : ";
my $media = <STDIN>;
chomp $media;

my $hash = "OK => [$tea_coffee] => [$wine] => [$shower] => [$morning] => [$night] => [$number] => [$word] => [$bday] => [$media].";

print "\n\n PLEASE REMEMBER THE BELOW and REMEMBER IT's CASE SENSITIVE:\n$hash\n\n";
print "If you are HAPPY to CONTINUE then please press 'y' => ";
ReadMode 4; # Turn off controls keys
my $yes = ReadKey(0);
ReadMode 0; # Turn off controls keys
if ( $yes eq 'y' or $yes eq 'Y' ) {
  system 'clear';
}
else {
  system 'clear';
  print "Aborted.\n";
  exit 1;
}

print "Now creating your password... this will take from 20 minutes to 40 minutes.....";
$hash    =  sha512_hex (from_hex('8ead637784bc4b35d82a630e47f0efd5f943aeb66137c89db66de8c7d4e6f0983c8a6b6ae9200409') . $hash);
my $salt =  from_hex(sha512_hex (from_hex($hash) . "some_pepper, may as well...."));
print "\n";
print "Using : [$hash].\n";
print "\n\nPassword creation in-progres... come back in 30 minutes.....";
my $start_time = time();
my $secret =  sha512_hex ( argon2id_raw ( from_hex($hash), $salt, 32768, '64M', 1, 32 ) );
print "\nSECRET =>   [$secret]\n\n";







sub from_hex {
  return pack 'H*', $_[0] if $_[0];
  return;
}


