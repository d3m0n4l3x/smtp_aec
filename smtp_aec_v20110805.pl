#!/usr/bin/perl -w
use IO::Socket;
use MIME::Base64 ();
$|=1;

print "\n";
print "********************************************\n";
print "** Welcome to use Anonymous Email Checker **\n";
print '**           demonalex@163.com            **'."\n";
print "********************************************\n";
print "\n";

print "Test Case 1th ... authenticate is not required!\n";
print "Explanation : The SMTP server can be exploited without authenticate.\n";
print "Target host: ";
$smtp_host=<STDIN>;
chop($smtp_host);
die "SMTP HOST is required!\n" if $smtp_host eq "";
print "Fake mail of Sender: ";
$smtp_sender=<STDIN>;
chop($smtp_sender);
die "SMTP SENDER is required!\n" if $smtp_sender eq "";
print "Receiving mail: ";
$real_receiver=<STDIN>;
chop($real_receiver);
die "RECEIVEING MAIL is required!\n" if $real_receiver eq "";
$smtp_port=25;
$mail_content_payload="authenticate is not required!\n";
undef($tmp_content);
$sock=IO::Socket::INET->new(PeerAddr=>$smtp_host,PeerPort=>$smtp_port,Timeout=>60);
if(defined($sock)){
	$sock->recv($tmp_content, 500, 0);                      #banner [220]
	$sock->send("EHLO mail_of_alert\r\n", 0);
	$sock->recv($tmp_content, 500, 0);                      #banner detail [250]
	sleep(2);
	$sock->send("MAIL FROM: <"."$smtp_sender".">\r\n", 0);
	sleep(2);
	$sock->recv($tmp_content, 500, 0);                      #Mail OK [250]
	sleep(2);
	$sock->send("RCPT TO: <"."$real_receiver".">\r\n", 0);
	sleep(2);
	$sock->recv($tmp_content, 500, 0);                      #Mail OK [250]
	sleep(2);
	$sock->send("Data\r\n", 0);
	sleep(2);
	$sock->recv($tmp_content, 500, 0);                      #End data with <CR><LF>.<CR><LF> [354]
	sleep(2);
	$sock->send("From: "."\"$smtp_sender\" <$smtp_sender>\r\n"."To: "."\"$real_receiver\" <$real_receiver>\r\n".
	"Subject: "."$mail_content_payload"."\r\n\r\n"."\x2e"."\r\n", 0);
	sleep(5);
	$sock->send("QUIT\r\n", 0);
	$sock->close;
}else{
	print "$smtp_host -> $smtp_port is closed!\n";
	exit(1);
}
print "Please check your receiving mail \'$real_receiver\'!\n";
print "Press [ENTER] to continue ...";
<STDIN>;
print "\n";

print "Test Case 2nd ... sender can be fake!\n";
print "Explanation : The sender can be fake after authenticate.\n";
print "Target host: ";
undef($smtp_host);
$smtp_host=<STDIN>;
chop($smtp_host);
die "SMTP HOST is required!\n" if $smtp_host eq "";
print "Fake mail of Sender: ";
undef($smtp_sender);
$smtp_sender=<STDIN>;
chop($smtp_sender);
die "SMTP SENDER is required!\n" if $smtp_sender eq "";
print "Receiving mail: ";
undef($real_receiver);
$real_receiver=<STDIN>;
chop($real_receiver);
die "RECEIVEING MAIL is required!\n" if $real_receiver eq "";
$smtp_port=25;
print "Username of SMTP: ";
$smtp_username=<STDIN>;
chop($smtp_username);
die "SMTP USERNAME is required!\n" if $smtp_username eq "";
print "Password of SMTP: ";
$smtp_password=<STDIN>;
chop($smtp_password);
die "SMTP PASSWORD is required!\n" if $smtp_password eq "";
$mail_content_payload="sender can be fake!\n";
undef($tmp_content);
$real_username=MIME::Base64::encode($smtp_username);
$real_password=MIME::Base64::encode($smtp_password);
$sock2=IO::Socket::INET->new(PeerAddr=>$smtp_host,PeerPort=>$smtp_port,Timeout=>60);
if(defined($sock2)){
	$sock2->recv($tmp_content, 500, 0);                      #banner [220]
	$sock2->send("EHLO mail_of_alert\r\n", 0);
	$sock2->recv($tmp_content, 500, 0);                      #banner detail [250]
	sleep(2);
	$sock2->send("AUTH LOGIN\r\n", 0);
	sleep(2);
	$sock2->recv($tmp_content, 500, 0);                      #require username [334]
	sleep(2);
	$sock2->send("$real_username", 0);
	sleep(2);
	$sock2->recv($tmp_content, 500, 0);                      #require password [334]
	sleep(2);
	$sock2->send("$real_password", 0);
	sleep(2);
	$sock2->recv($tmp_content, 500, 0);                      #auth successful [235]
	sleep(2);
	$sock2->send("MAIL FROM: <"."$smtp_sender".">\r\n", 0);
	sleep(2);
	$sock2->recv($tmp_content, 500, 0);                      #Mail OK [250]
	sleep(2);
	$sock2->send("RCPT TO: <"."$real_receiver".">\r\n", 0);
	sleep(2);
	$sock2->recv($tmp_content, 500, 0);                      #Mail OK [250]
	sleep(2);
	$sock2->send("Data\r\n", 0);
	sleep(2);
	$sock2->recv($tmp_content, 500, 0);                      #End data with <CR><LF>.<CR><LF> [354]
	sleep(2);
	$sock2->send("From: "."\"$smtp_username\" <$smtp_sender>\r\n"."To: "."\"$real_receiver\" <$real_receiver>\r\n".
	"Subject: "."$mail_content_payload"."\r\n\r\n"."\x2e"."\r\n", 0);
	sleep(5);
	$sock2->send("QUIT\r\n", 0);
	$sock2->close;
}else{
	print "$smtp_host -> $smtp_port is closed!\n";
	exit(1);
}
print "Please check your receiving mail \'$real_receiver\'!\n";
print "Press [ENTER] to continue ...";
<STDIN>;
print "\n";

print "Test Case 3rd ... MUA can be fake!\n";
print "Explanation : MUA can be fake with validated user.\n";
print "Target host: ";
undef($smtp_host);
$smtp_host=<STDIN>;
chop($smtp_host);
die "SMTP HOST is required!\n" if $smtp_host eq "";
print "Fake mail of Sender: ";
undef($smtp_sender);
$smtp_sender=<STDIN>;
chop($smtp_sender);
die "SMTP SENDER is required!\n" if $smtp_sender eq "";
print "Real mail of Sender: ";
$real_sender=<STDIN>;
chop($real_sender);
die "REAL MAIL is required!\n" if $real_sender eq "";
print "Receiving mail: ";
undef($real_receiver);
$real_receiver=<STDIN>;
chop($real_receiver);
die "RECEIVEING MAIL is required!\n" if $real_receiver eq "";
$smtp_port=25;
print "Username of SMTP: ";
$smtp_username=<STDIN>;
chop($smtp_username);
die "SMTP USERNAME is required!\n" if $smtp_username eq "";
print "Password of SMTP: ";
$smtp_password=<STDIN>;
chop($smtp_password);
die "SMTP PASSWORD is required!\n" if $smtp_password eq "";
$mail_content_payload="MUA can be fake!\n";
undef($tmp_content);
$real_username=MIME::Base64::encode($smtp_username);
$real_password=MIME::Base64::encode($smtp_password);
$sock3=IO::Socket::INET->new(PeerAddr=>$smtp_host,PeerPort=>$smtp_port,Timeout=>60);
if(defined($sock3)){
	$sock3->recv($tmp_content, 500, 0);                      #banner [220]
	$sock3->send("EHLO mail_of_alert\r\n", 0);
	$sock3->recv($tmp_content, 500, 0);                      #banner detail [250]
	sleep(2);
	$sock3->send("AUTH LOGIN\r\n", 0);
	sleep(2);
	$sock3->recv($tmp_content, 500, 0);                      #require username [334]
	sleep(2);
	$sock3->send("$real_username", 0);
	sleep(2);
	$sock3->recv($tmp_content, 500, 0);                      #require password [334]
	sleep(2);
	$sock3->send("$real_password", 0);
	sleep(2);
	$sock3->recv($tmp_content, 500, 0);                      #auth successful [235]
	sleep(2);
	$sock3->send("MAIL FROM: <"."$real_sender".">\r\n", 0);
	sleep(2);
	$sock3->recv($tmp_content, 500, 0);                      #Mail OK [250]
	sleep(2);
	$sock3->send("RCPT TO: <"."$real_receiver".">\r\n", 0);
	sleep(2);
	$sock3->recv($tmp_content, 500, 0);                      #Mail OK [250]
	sleep(2);
	$sock3->send("Data\r\n", 0);
	sleep(2);
	$sock3->recv($tmp_content, 500, 0);                      #End data with <CR><LF>.<CR><LF> [354]
	sleep(2);
	$sock3->send("From: "."\"$smtp_sender\" <$smtp_sender>\r\n"."To: "."\"$real_receiver\" <$real_receiver>\r\n".
	"Subject: "."$mail_content_payload"."\r\n\r\n"."\x2e"."\r\n", 0);
	sleep(5);
	$sock3->send("QUIT\r\n", 0);
	$sock3->close;
}else{
	print "$smtp_host -> $smtp_port is closed!\n";
	exit(1);
}
print "Please check your receiving mail \'$real_receiver\'!\n";
print "Press [ENTER] to continue ...";
<STDIN>;
print "\n";

print "Game over!";
exit(1);