#!/usr/bin/perl -w 

use strict;
use warnings;
use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha384 sha512 sha512_hex sha512_base64 sha256 sha256_hex sha256_base64 hmac_sha256 hmac_sha256_base64 hmac_sha256_hex hmac_sha512 hmac_sha512_base64);
use MIME::Base64;
use Crypt::CBC qw(random_bytes);
use Compress::Zlib;
use Crypt::OpenSSL::RSA;
use RPC::XML qw(:types);
use RPC::XML::Client;
use Data::Dumper;
use Encode;
#use Net::SSLGlue::LWP;   #try this voodoo if u r getting buttpain establishing https connections for your personalized feeds or upgrade to libwww-perl 6.05-2 and liblwp-protocol-https-perl 6.04-2 (that would be a better solution indeed, enabling this will bring issues when trying to connect to Twitter API)
use LWP::UserAgent;
use LWP::Protocol::https;
use LWP::Protocol::socks;
use JSON;
use FindBin; 
use Net::Twitter::Lite::WithAPIv1_1;
use XML::FeedPP;
use POSIX;


    
#	   LICENSE
#	   -------
    
	  ##############################################
	  ##             LulzSec License              ##
	  ##                                          ##
	  ## Do whatever you fucking want with this,  ##
	  ## but you must produce at least one act of ##
	  ## civil disobedience against the System    ##
	  ## and its rules, even if that represents   ##
	  ## not honoring this license at all.        ##
	  ## Fuck Cops' daughters, send cigarettes    ##
	  ## to those of us who are jailed, smash     ##
	  ## down CCTV cameras and...                 ##
	  ## also cocks, because lulz.                ##
	  ##                                          ##
	  ##############################################





my $pid;
my $ZonkeyPort = '8080';
#my $mustListenAllInterfaces = "nones";
my $mustListenAllInterfaces = "yeah";


my $fldigi_xmlrpc_server_url = 'http://localhost:7362/RPC2';

my $macroTX = 11;

my $currentmodem = 'PSK500R';
my $frequencycarrier = '1500';

my $mustEncrypt = "nones";
my $passphrase = 'x3UstrV@HlpressssssssuckXZ$O^;55jlT*'; #default, cause it should have one at least, pl0x change this.

my $mustUseCallSign = "nones";
my $callsign;


my $mustNewsBroadcast = "nones";
my @rssfeeds = ("http://www.nytimes.com/services/xml/rss/nyt/HomePage.xml", "http://www.guardian.co.uk/rssfeed/0,,1,00.xml", "http://newsrss.bbc.co.uk/rss/newsonline_world_edition/front_page/rss.xml", "http://www.npr.org/rss/rss.php?id=2", "http://www.huffingtonpost.com/thenewswire/full_rss.rdf", "http://www.nytimes.com/services/xml/rss/nyt/International.xml", "http://www.washingtonpost.com/wp-dyn/rss/world/index.xml", "http://www.npr.org/rss/rss.php?id=1004", "http://wired.com/rss/index.xml");

my $mustCommunityBroadcast = "nones";
my @communityfeeds;

my $mustTweetOthers = "nones";
my $mustTweetBroadcast ="nones";


my $twitterhashtag2follow = "#zonkeynet";
my $searchtwtterm;

######## @ZonkeyNet twitter account ###
my $consumer_key_default="rH0XHij4BOdc5DmFFRbTw";
my $consumer_secret_default="GIyl3vPtSr0t9JLVSuE8HIVj5I3HNXClCoUa7cdNqQ";
my $access_token_default="2386106611-hLQTnLQpvnnsuiV0aZB2HvAC2fVRqUUEc1dvP5n";
my $access_token_secret_default="td6RSOUPMjVUc74LTjUIOsPgQqIrzAk5ZQjsXDPh7ZRK8";


my $consumer_key="rH0XHij4BOdc5DmFFRbTw";
my $consumer_secret="GIyl3vPtSr0t9JLVSuE8HIVj5I3HNXClCoUa7cdNqQ";
my $access_token="2386106611-hLQTnLQpvnnsuiV0aZB2HvAC2fVRqUUEc1dvP5n";
my $access_token_secret="td6RSOUPMjVUc74LTjUIOsPgQqIrzAk5ZQjsXDPh7ZRK8";


my $mustUseProxy = "nones";

my $torproxyhost = "127.0.0.1";
my $torproxyport = "9050";

my $proxyhost = "127.0.0.1";
my $proxyport = "8118";
my $proxyuser;
my $proxypass;

my $settings;

my @messagessent;
my @askedresend;
my @answeredresend;
my @alreadyasked;

my @newmessages;

my $currentmessages;
my $currentlogtxt;

my @donedecodedmsgs;

my $twitterResults;

my $checknews = "nones";
my $checkcommunity = "nones";
my $checktwitter = "nones";


my $mustAsk2resend = "nones";
my $mustAnswerResendreq = "nones";

my $cryptidx = '000000';

my $buildRoutes = 'yeah';

my $lastcheck = 0;
my $lastcheckrsnd = 0;

my $foolder = $FindBin::Bin;

my (%dahfuckingkeys);

my (%rtable);

umask(077);

my (%awesomessages);

sub save_settings {
	
	$settings->{'settings'}{'ZonkeyNet Server'}{'fldigi_xmlrpc_server_url'} = $fldigi_xmlrpc_server_url ;
	$settings->{'settings'}{'ZonkeyNet Server'}{'ZonkeyPort'} = $ZonkeyPort ;
	$settings->{'settings'}{'ZonkeyNet Server'}{'mustListenAllInterfaces'} = $mustListenAllInterfaces ;
	$settings->{'settings'}{'Modem Settings'}{'mustAsk2resend'} = $mustAsk2resend ;
	$settings->{'settings'}{'Modem Settings'}{'mustAnswerResendreq'} = $mustAnswerResendreq ;
	$settings->{'settings'}{'Modem Settings'}{'currentmodem'} = $currentmodem ;
	$settings->{'settings'}{'Modem Settings'}{'frequencycarrier'} = $frequencycarrier ;
	$settings->{'settings'}{'Modem Settings'}{'mustEncrypt'} = $mustEncrypt ;
	$settings->{'settings'}{'Modem Settings'}{'passphrase'} = $passphrase ; #default, change this 
    $settings->{'settings'}{'Modem Settings'}{'mustUseCallSign'} = $mustUseCallSign ;
    $settings->{'settings'}{'Modem Settings'}{'callsign'} = $callsign ;
	$settings->{'settings'}{'Feeds'}{'mustNewsBroadcast'} = $mustNewsBroadcast;
	$settings->{'settings'}{'Feeds'}{'mustCommunityBroadcast'} = $mustCommunityBroadcast ;
	$settings->{'settings'}{'Feeds'}{'rssfeeds'} = join("   ", @rssfeeds) ;
	$settings->{'settings'}{'Feeds'}{'communityfeeds'} = join("   ", @communityfeeds) ;
	$settings->{'settings'}{'Twitter'}{'mustTweetOthers'} = $mustTweetOthers ;
	$settings->{'settings'}{'Twitter'}{'mustTweetBroadcast'} = $mustTweetBroadcast ;
	$settings->{'settings'}{'Twitter'}{'consumer_key'} = $consumer_key ;
	$settings->{'settings'}{'Twitter'}{'consumer_secret'} = $consumer_secret ;
	$settings->{'settings'}{'Twitter'}{'access_token'} = $access_token ;
	$settings->{'settings'}{'Twitter'}{'access_token_secret'} = $access_token_secret ; 
	$settings->{'settings'}{'Tor and Proxy'}{'mustUseProxy'} = $mustUseProxy ;
	$settings->{'settings'}{'Tor and Proxy'}{'torproxyhost'} = $torproxyhost ;
	$settings->{'settings'}{'Tor and Proxy'}{'torproxyport'} = $torproxyport ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxyhost'} = $proxyhost ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxyport'} = $proxyport ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxyuser'} = $proxyuser ;
	$settings->{'settings'}{'Tor and Proxy'}{'proxypass'} = $proxypass ;
	$settings->{'settings'}{'penis'}{'penis'} = 'also cocks' ;
	
	
	  open( F, '>', "$foolder/.ZonkeyNetsettings");
	     print F JSON->new->utf8->pretty(1)->encode($settings);
	   close(F);

}



sub load_settings {
	print $FindBin::Bin;
	my $configfile;
	
	
	if ( -e "$foolder/.ZonkeyNetsettings" ) {
		                open(F, '<', "$foolder/.ZonkeyNetsettings") or die "cannot open file settings";
		              {
		                 local $/;
		                  $configfile = <F>;
		                }
		                close(F);
		               
	
	
	my $json = JSON->new;
    $settings = $json->allow_nonref->utf8->relaxed->decode($configfile);
    
   
    
 $fldigi_xmlrpc_server_url = $settings->{'settings'}{'ZonkeyNet Server'}{'fldigi_xmlrpc_server_url'}  if defined  $settings->{'settings'}{'ZonkeyNet Server'}{'fldigi_xmlrpc_server_url'}  ;
 $ZonkeyPort = $settings->{'settings'}{'ZonkeyNet Server'}{'ZonkeyPort'} if defined $settings->{'settings'}{'ZonkeyNet Server'}{'ZonkeyPort'} ;
 $mustListenAllInterfaces = $settings->{'settings'}{'ZonkeyNet Server'}{'mustListenAllInterfaces'}  if defined  $settings->{'settings'}{'ZonkeyNet Server'}{'mustListenAllInterfaces'}  ;
 $mustAsk2resend = $settings->{'settings'}{'Modem Settings'}{'mustAsk2resend'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustAsk2resend'}  ;
 $mustAnswerResendreq = $settings->{'settings'}{'Modem Settings'}{'mustAnswerResendreq'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustAnswerResendreq'}  ;
 $currentmodem = $settings->{'settings'}{'Modem Settings'}{'currentmodem'}  if defined  $settings->{'settings'}{'Modem Settings'}{'currentmodem'}  ;
 $frequencycarrier = $settings->{'settings'}{'Modem Settings'}{'frequencycarrier'}  if defined  $settings->{'settings'}{'Modem Settings'}{'frequencycarrier'}  ;
 $mustEncrypt = $settings->{'settings'}{'Modem Settings'}{'mustEncrypt'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustEncrypt'}  ;
 $passphrase  = $settings->{'settings'}{'Modem Settings'}{'passphrase'}  if defined  $settings->{'settings'}{'Modem Settings'}{'passphrase'}  ;
 $mustUseCallSign = $settings->{'settings'}{'Modem Settings'}{'mustUseCallSign'}  if defined  $settings->{'settings'}{'Modem Settings'}{'mustUseCallSign'}  ;
 $callsign  = $settings->{'settings'}{'Modem Settings'}{'callsign'}  if defined  $settings->{'settings'}{'Modem Settings'}{'callsign'}  ;
 $mustNewsBroadcast = $settings->{'settings'}{'Feeds'}{'mustNewsBroadcast'}  if defined  $settings->{'settings'}{'Feeds'}{'mustNewsBroadcast'}  ;
 $mustCommunityBroadcast = $settings->{'settings'}{'Feeds'}{'mustCommunityBroadcast'}  if defined  $settings->{'settings'}{'Feeds'}{'mustCommunityBroadcast'}  ;
 @rssfeeds = split("   ", $settings->{'settings'}{'Feeds'}{'rssfeeds'})  if defined  $settings->{'settings'}{'Feeds'}{'rssfeeds'}  ;
 @communityfeeds = split("   ", $settings->{'settings'}{'Feeds'}{'communityfeeds'})  if defined  $settings->{'settings'}{'Feeds'}{'communityfeeds'}  ;
 $mustTweetOthers = $settings->{'settings'}{'Twitter'}{'mustTweetOthers'}  if defined  $settings->{'settings'}{'Twitter'}{'mustTweetOthers'}  ;
 $mustTweetBroadcast = $settings->{'settings'}{'Twitter'}{'mustTweetBroadcast'}  if defined  $settings->{'settings'}{'Twitter'}{'mustTweetBroadcast'}  ;
 $consumer_key = $settings->{'settings'}{'Twitter'}{'consumer_key'}  if defined  $settings->{'settings'}{'Twitter'}{'consumer_key'}  ;
 $consumer_secret = $settings->{'settings'}{'Twitter'}{'consumer_secret'}  if defined  $settings->{'settings'}{'Twitter'}{'consumer_secret'}  ;
 $access_token = $settings->{'settings'}{'Twitter'}{'access_token'}  if defined  $settings->{'settings'}{'Twitter'}{'access_token'}  ;
 $access_token_secret  = $settings->{'settings'}{'Twitter'}{'access_token_secret'}  if defined  $settings->{'settings'}{'Twitter'}{'access_token_secret'}  ;
 $mustUseProxy = $settings->{'settings'}{'Tor and Proxy'}{'mustUseProxy'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'mustUseProxy'}  ;
 $torproxyhost = $settings->{'settings'}{'Tor and Proxy'}{'torproxyhost'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'torproxyhost'}  ;
 $torproxyport = $settings->{'settings'}{'Tor and Proxy'}{'torproxyport'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'torproxyport'}  ;
 $proxyhost = $settings->{'settings'}{'Tor and Proxy'}{'proxyhost'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxyhost'}  ;
 $proxyport = $settings->{'settings'}{'Tor and Proxy'}{'proxyport'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxyport'}  ;
 $proxyuser = $settings->{'settings'}{'Tor and Proxy'}{'proxyuser'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxyuser'}  ;
 $proxypass = $settings->{'settings'}{'Tor and Proxy'}{'proxypass'}  if defined  $settings->{'settings'}{'Tor and Proxy'}{'proxypass'}  ;


     }else{
		 save_settings();
	 }
}

load_settings();

sub save_messages {
	
	my $sv = \%awesomessages;
	  open( F, '>', "$foolder/.AirChatLog.json");
	     print F JSON->new->utf8->encode($sv);
	   close(F);

}

sub load_messages {
	
    my $msgfile;
	
	
	if ( -e "$foolder/.AirChatLog.json" ) {
		                open(F, '<', "$foolder/.AirChatLog.json") or die "cannot open file messages";
		              {
		                 local $/;
		                  $msgfile = <F>;
		                }
		                close(F);
		               
	
	
	my $json = JSON->new;
    my $getem = $json->allow_nonref->utf8->relaxed->decode($msgfile);
    
    %awesomessages = %{$getem};
    
  }
}

load_messages();


sub save_keys {
	
	my $sv = \%dahfuckingkeys;
	  open( F, '>', "$foolder/.Zonkeys");
	     print F JSON->new->utf8->encode($sv);
	   close(F);

}

sub load_keys {
	
    my $keysfile;
	
	
	if ( -e "$foolder/.Zonkeys" ) {
		                open(F, '<', "$foolder/.Zonkeys") or die "cannot open file keys";
		              {
		                 local $/;
		                  $keysfile = <F>;
		                }
		                close(F);
		               
	
	
	my $json = JSON->new;
    my $getem = $json->allow_nonref->utf8->relaxed->decode($keysfile);
    
    %dahfuckingkeys = %{$getem};
    
  }else{
	  
	  
	  my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
	  
	  my $keyidx = $rsa->get_public_key_string() if defined $rsa;

	    $keyidx = sha512_hex($keyidx,"");
	    $keyidx = substr($keyidx,0,6);	 
	     
	  $dahfuckingkeys{$keyidx}{'pubK'}  = $rsa->get_public_key_string();
	  $dahfuckingkeys{$keyidx}{'privK'} = $rsa->get_private_key_string();
      $dahfuckingkeys{$keyidx}{'Local'} = 1;
      
      save_keys();
  }
}

load_keys();


sub create_another_localkey {
	
	
	  my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
	  
	  my $keyidx = $rsa->get_public_key_string() if defined $rsa;
	
	    $keyidx = sha512_hex($keyidx,"");
	    $keyidx = substr($keyidx,0,6);	 
	     
	  $dahfuckingkeys{$keyidx}{'pubK'}  = $rsa->get_public_key_string();
	  $dahfuckingkeys{$keyidx}{'privK'} = $rsa->get_private_key_string();
      $dahfuckingkeys{$keyidx}{'Local'} = 1;
      
      save_keys();
      
}



################################################################

sub twitter_load_tokens {


  $ENV{HTTPS_PROXY} = 'socks://127.0.0.1:9050';
    my $usetheshit = 0;
    
    if ($mustUseProxy eq "useProxy" ) {
	
	my $proxy = $proxyhost . ":" . $proxyport;
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
	$ENV{HTTPS_PROXY}               = "$proxy";
	$ENV{HTTP_PROXY}                = "$proxy";
    #$ENV{CGI_HTTP_PROXY}            = "$proxy";
    #$ENV{CGI_HTTPS_PROXY}           = "$proxy";
	
	if ($proxyuser && length($proxyuser) > 2 ) { 
	$ENV{HTTPS_PROXY_USERNAME}      = "$proxyuser";
	$ENV{HTTP_PROXY_USERNAME}       = "$proxyuser"; 
    }
	if ( $proxypass && length($proxypass) > 2) {
	$ENV{HTTP_PROXY_PASSWORD}       = "$proxypass"; 
    $ENV{HTTPS_PROXY_PASSWORD}      = "$proxypass";  
     }
     $usetheshit = 1;
	}
	
     if ($mustUseProxy eq "useTor" ) {

		 my $torproxy = 'socks://' . $torproxyhost . ':' . $torproxyport;     # Tor proxy
	$ENV{HTTPS_PROXY}              = "$torproxy";
	$ENV{HTTP_PROXY}               = "$torproxy"; 
	#$ENV{CGI_HTTP_PROXY}           = "$torproxy";
	#$ENV{CGI_HTTPS_PROXY}          = "$torproxy";
	$usetheshit = 1;
      } 
  
  my $nt = Net::Twitter::Lite::WithAPIv1_1->new(
    consumer_key    => $consumer_key,
    consumer_secret => $consumer_secret,
    useragent => 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36',
    clientname => 'Air',
    clientver => '1.1',
    clienturl => 'https://github.com/lulzlabs',
    source => 'cock',
      
    useragent_args => {'env_proxy' => $usetheshit,},
    
    ssl => 1,
  );
  $nt->access_token($access_token);
  $nt->access_token_secret($access_token_secret);

  return $nt;
  
}

sub twitter_searching {

   my $searchkeyword = join("", @_);
   
    my $nt = twitter_load_tokens();
    
    if (!$searchkeyword) {
      $searchkeyword = $twitterhashtag2follow ;
    }

    if (length("$searchkeyword") < 2 ) {
       $searchkeyword = $twitterhashtag2follow ;
    }



   my $r =();
    eval {$r = $nt->search("$searchkeyword", { count => 10 })};
     if ( $@ ) {
                print "twtter: hey! :( search failed cause: $@\n";
            }else {
				
			}

    my @results = ();
    
    #$twitterResults = Dumper($r->{statuses});  #lelelele


    for my $tweet ( @{$r->{statuses}} ) { 

       my @item = ();

            @item = ( encode_utf8($tweet->{user}{screen_name}) , encode_utf8($tweet->{user}{name}) ,
                encode_utf8($tweet->{text}));

        push @results, \@item;
    }
    my @result;
    foreach (@results) {
       
       my @array=$_;
       my $name=$array[0][0];
       my $scrname=$array[0][1];
       my $text=$array[0][2];
 
        my $twit= "@" . "$name ($scrname):\n $text";
        chomp($twit);
        push @result, $twit;

   }
    

        my $retrn = join("\n\n-----\n\n",@result);
        
      return($retrn);  

}

sub twitter_check_mentions {

    my $nt = twitter_load_tokens();

    my $replies = $nt->mentions();
    my @results = ();
    my $twit;
    for my $tweet ( @$replies ) {
        my @item = ();
        if ( $tweet->{retweeted_status} ) {
            @item = ( encode_utf8($tweet->{user}{screen_name}) ,
                encode_utf8($tweet->{retweeted_status}{text}) ,
                encode_utf8($tweet->{retweeted_status}{created_at}));
        } else {
            @item = ( encode_utf8($tweet->{user}{screen_name}) ,
                encode_utf8($tweet->{text}) ,
                encode_utf8($tweet->{created_at}));
        }
        push @results, \@item;
    }
    my @result;
    foreach (@results) {
        
        my @array=$_;
        my $name=$array[0][0];
        my $text=$array[0][1];
        my $date=$array[0][2];

      
        $twit= "$name :  $text  - $date";
        chomp($twit);
        push @result, $twit;
 
   }
  
   my $retrn = join("\n\n",@result);
      
      return($retrn);  

}

sub twitter_msg {
  
  


  if (@_) {
    my $msg = join("", @_);
    
    my $nt = twitter_load_tokens();
    
    if (length("$msg") >= 140) {
		$msg = substr($msg,0,140);
	}
    
			my $tweet;
            eval { $tweet = $nt->update("$msg") };          
            if ( $@ ) {
                 print "twtter: hey! :( update failed because: $@\n";
               
            }else{
		      my $twttuser = encode_utf8($tweet->{user}{screen_name});
		      my $statusid = encode_utf8($tweet->{id_str});
		      my $returntweetlink = 'https://twitter.com/' . $twttuser . '/status/' . $statusid ;
              return($returntweetlink);     #for privacy related reasons we are not sure if we will use this returned link, if you want so just do it
            }

  }

}

#####################################################################

sub announce_list {
	

	my @contactstopost;
    my @announcestopost;
	foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( $dahfuckingkeys{$publickey}{'Local'} ) {
		  
		    my $cidx = $publickey;
            push(@announcestopost,$cidx);
  
	   }
		  
	  }
	
	
	
	foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canTalk'} ) {
		  
		    my $kidx = $contacted;
           push(@contactstopost,$kidx) if defined $kidx;
	   }
		  
	  }
	
	my $postallcontacts = join(":",@contactstopost);
	
	my @stufftodispatch;
	if (@announcestopost) {
	foreach my $announce (@announcestopost) {
		my $heyholetsgo;
		if ( @contactstopost ) {
		$heyholetsgo = "HOTEL-INDIA [ANNOUNCE:" . $announce . ":CTALK2:" . $postallcontacts . "]##END##";

	    }else{
	    $heyholetsgo = "HOTEL-INDIA [ANNOUNCE:" . $announce . "]##END##";

		}
		push(@stufftodispatch,$heyholetsgo);
	}
   
   my $postall = join("   ",@stufftodispatch);
   return $postall if defined $postall;
   }
}


sub receive_announce {
	  
	  
	  if (@_) {
	   my $pack = join("",@_);
	   if ($pack) {
	   my @sendhelloback;
	   my @sortedshit = split("##END##",$pack);
		
		
		for (my $i = 0 ; $i < scalar(@sortedshit); $i++) {
	
			
			if ($sortedshit[$i] =~ m/\[ANNOUNCE:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				my @kxcode = split("ANNOUNCE:",$sortedshit[$i],2);
				my $kidx = substr($kxcode[1],0,6);
				
				if (!$dahfuckingkeys{$kidx}{'Local'}) {
	            push(@sendhelloback,$kidx) if defined $kidx;
			    $rtable{$kidx}{'canListen'} = 1 if $kidx;
				
				if ($kxcode[1] =~ m/:CTALK2:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				$kxcode[1] =~ s/\](.*)$/ / ;
				my @crackpart = split(":CTALK2:",$kxcode[1]);
				my @extcodes = split(":",$crackpart[1]);
				
				foreach my $codx (@extcodes) {
			    if ( $codx =~ m/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				my $cidx = substr($codx,0,6);
				if (!$dahfuckingkeys{$cidx}{'Local'} || !$rtable{$cidx}{'canTalk'}) {
				$rtable{$cidx}{'canTalkExtended'} = 1 if defined $cidx;
				$rtable{$cidx}{'via'} = $kidx;
			     }
				
			     }
                 
                 }
			
                }
                
			  }

         }
       }
      
    my $posthiback;      
    if (@sendhelloback)   {
	my @hiback;
	 my $postitall;
    $postitall = join(":",@sendhelloback);
    
    foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( $dahfuckingkeys{$publickey}{'Local'} ) {
		  
		    my $codx = $publickey;
		    my $postgreetz = "HOTEL-INDIA [OHAITHERE:" . $postitall . ":" . "][HEREIZ:$codx]##END##";  ## adding some padding
            push(@hiback,$postgreetz);
            
	   }
		  
	  }
	$posthiback = join("  ",@hiback);
    }
	return $posthiback if defined $posthiback;
   }
	
 }
}


sub build_list {
	
     if (@_) {
	   my $pack = join("",@_);
   
	   if ($pack) {
	   my @sortedshit = split("##END##",$pack);
		
		
		for (my $i = 0 ; $i < scalar(@sortedshit); $i++) {
	
			
			if ($sortedshit[$i] =~ m/\[OHAITHERE:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				
				my @kxcodes = split("OHAITHERE:",$sortedshit[$i],2);
				
				if ($sortedshit[$i] =~ m/\[HEREIZ:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) { 

				my @gethelloer = split("HEREIZ:",$kxcodes[1]);
				my $reachedidx = substr($gethelloer[1],0,6);
				$kxcodes[1] =~ s/\](.*)$/ / ;
				my @lotidx = split(":",$kxcodes[1]);
				
				foreach my $kidx (@lotidx) {
			    if ( $kidx =~ m/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
				my $kidx = substr($kidx,0,6);
				
				if ( $dahfuckingkeys{$kidx}{'Local'} ) {
				$rtable{$reachedidx}{'canTalk'} = 1 if defined $kidx;
				delete $rtable{$reachedidx}{'canTalkExtended'} if defined $kidx;
			     }
				
			     }
               }
		   }
         }
       }
       
   }
   
  }
}


###################################################################

sub asymm_encrypt {
	
	if (@_) {
		
	my ($keycode, $txpack) = @_;
	

	    my $dahpassiez;
		$dahpassiez = Crypt::CBC->random_bytes('4096');
	    $dahpassiez = sha256_base64($dahpassiez,"");	
	
	if ( $dahfuckingkeys{$keycode} && $dahfuckingkeys{$keycode}{'pubK'} ) {
		
		my $pubKstring = $dahfuckingkeys{$keycode}{'pubK'} ;
		my $public_rsa = Crypt::OpenSSL::RSA->new_public_key($pubKstring) || die "$!";
        
        my $cpassie = $public_rsa->encrypt($dahpassiez);
		my $ctx;
	  my $useThisk = '000000';
	  		            
	  		             if ( $dahpassiez) {	

						 	 foreach my $kidx ( keys %dahfuckingkeys) {
                                if ( $dahfuckingkeys{$kidx}{'Local'} ) {
				                   $useThisk = $kidx ;
			                     }
				             } 
							 
							 		
						   my $cipher = Crypt::CBC->new(
			         {    
			           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
			
		               'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
			       #    'cipher'        => 'Camellia_PP',
			
			           'padding'       => 'standard',
			    
			        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
			         }
			        );
		
		
		             $cipher->{'passphrase'} = $dahpassiez;

		             eval{$ctx = $cipher->encrypt($txpack)};
		             eval{$useThisk = $cipher->encrypt($useThisk)};
					             if ($@) {
						 print "error encrypting";
						
					 }else {

						 
						 $useThisk = encode_base64($useThisk,"");
						 $cpassie = encode_base64($cpassie,"");
						 $ctx = encode_base64($ctx,"");
						 
						 my $readypack = $cpassie .'</Key>'. $useThisk . '</reply>' . $ctx ;
						 return ($readypack);
					 }	     
				     
				     }
	  
	  
	  
	  
	  }
	
	
   }


  
}



######


sub asymm_decrypt {
	
	if (@_) {
		
	my ($keycode, $ctpack) = @_;

	 if ($ctpack =~ m/\<\/Key\>/ ) {
                my $septr = '</Key>';
                my @letbreak = split($septr,$ctpack);

		my $ctpass = $letbreak[0];
		my $ctpx = $letbreak[1];
		
		
		my $septr2 = '</reply>';
        my @break2 = split($septr2,$letbreak[1]);
        my $ctreply2 = $break2[0] ;
        my $ctx =  $break2[1] ;

				
		$ctpass = decode_base64($ctpass);
		$ctx = decode_base64($ctx);
		$ctreply2 = decode_base64($ctreply2);  
		
   
		   
	if ( $dahfuckingkeys{$keycode} && $dahfuckingkeys{$keycode}{'privK'} ) {
		
		my $privKstring = $dahfuckingkeys{$keycode}{'privK'} ;
		my $private = Crypt::OpenSSL::RSA->new_private_key($privKstring) || die "$!";

        my $passie = $private->decrypt($ctpass);
		my $plaintext;
	  
	  		             if ( $passie) {			
						   my $cipher = Crypt::CBC->new(
			         {    
			           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
			
		               'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
			       #    'cipher'        => 'Camellia_PP',
			
			           'padding'       => 'standard',
			    
			        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
			         }
			        );
		
		
		             $cipher->{'passphrase'} = $passie;

		             eval{$plaintext = $cipher->decrypt($ctx)};
		             eval{$ctreply2  = $cipher->decrypt($ctreply2)};
					             if ($@) {
						 print "error decrypting";
					
					 }else {
                         if ( $ctreply2 eq '000000' ) {
			               $plaintext = "ORIGIN: ---- \n\n" . $plaintext ;
		                 }else{
						   $plaintext = "ORIGIN: " . $ctreply2 . "\n\n" . $plaintext ;
						 }
		                 
                         
                         if ( $dahfuckingkeys{$ctreply2}{'name'} ) {
							 $plaintext = "REPLY-TO: " . $dahfuckingkeys{$ctreply2}{'name'} . "\n" . $plaintext ;
							 
						 }
                         
						 return ($plaintext);
					 }	     
				     
				     }
	  
	  
	  
	  
	  }
	
	
   }

 }
	
}



####################################################################

sub check_for_commands {
	
	if (@_) {
	my $lovelymsg = join("",@_);
	
	my $markitlocal;
	
	if ($lovelymsg =~ m/^:/ ) {
		
		if ($lovelymsg =~ m/^:local/ ) {
		
		$lovelymsg =~ s/^:local// ;
		$markitlocal = "yeah";
	    }

						 if ($mustNewsBroadcast eq "yeahcool") {
							  if ($lovelymsg =~ m/^:news?/) {
								  if ($markitlocal) {
								     my $newslines = fetch_rss(@rssfeeds);
								     $lovelymsg = $lovelymsg . "\n\n" . $newslines if defined $newslines;
							      }else{
									  $checknews = "yeah";
									 
									  }
							  }
						    }
						    if ($mustCommunityBroadcast eq "yeahcool") {
							  if ($lovelymsg =~ m/^:sup?/) {
								  if ($markitlocal) {
								  	  my $feedlines = fetch_rss(@communityfeeds);
								     $lovelymsg = $lovelymsg . "\n\n" . $feedlines if defined $feedlines;
							      }else{
									  $checkcommunity = "yeah";
									  }
							  }
						    }
						 if ($mustTweetOthers eq "yeahcool") {
							  if ($lovelymsg =~ m/^:tweet /) {
								  my $totweet = $lovelymsg ;
								  $totweet =~ s/^:tweet //;
								  my $candy = twitter_msg($totweet);
								  if ($markitlocal) {
									  
								    $lovelymsg = $lovelymsg . "\n\n" . $candy if defined $candy;
							      }else{
									  
									  }
								  
								  
							  }
						    }
						    
						    if ($mustTweetBroadcast eq "yeahcool") {
							
							  if ($lovelymsg =~ m/^:twitter/ ) {
								  
								 
								  
								  
								  
								 if ($markitlocal) {
									# $candy = encode_utf8($candy);
									my  $candy = twitter_searching();
								     $lovelymsg = $lovelymsg . "\n\n" . $candy if defined $candy;
							      }else{
                                             # changed to just answer last request
                                             $searchtwtterm = undef;
                                            $checktwitter = "yeah";
									  }
								 
							  }
						    }
						    if ($mustTweetBroadcast eq "yeahcool") {
							  if ($lovelymsg =~ m/^:searchtwitter=/) {
								  my @searchtweets = split("=", $lovelymsg, 3);
								  my @clnsearchtweets = split(" ",$searchtweets[1]);
								  
								  $searchtwtterm = $clnsearchtweets[0];
								  
								 if ($markitlocal) {
								
									my $candy = twitter_searching($searchtwtterm);
								    $lovelymsg = $lovelymsg . "\n\n" . $candy if defined $candy;
							      }else{ 
									  # changed to just answer last request
                                             $checktwitter = "yeah";
                                             
									  }
								  
								  
							  }
						    }

						 return($markitlocal,$lovelymsg);
	}
  }
}




sub sendingshits {
	
	
	
	
	if (@_) {
	
	my ($keyidx, $thestuff)	= @_;
	my $makeitlocal;
	my $lovelymsg = $thestuff;
	
	if ( $mustUseCallSign eq "yeah" && $callsign && length($callsign) > 2 ) {
	
	$lovelymsg = $lovelymsg . "\n\n----------\n\n" . "FROM CALLSIGN: " . $callsign . "\n" ; 	
		
	}
	
	my $hashin;
	
		my $ttmsgcode;
		$ttmsgcode = Crypt::CBC->random_bytes('128');
	    $ttmsgcode = sha512_hex($ttmsgcode,"");
	    $ttmsgcode=substr($ttmsgcode,0,6);
	
	if ($lovelymsg =~ m/^:/ ) {
		
		my ($isLocal,$chkdmessage) = check_for_commands($lovelymsg);
		
		return if $chkdmessage =~ m/^:trash/ ;
					 

                  if ($isLocal && $isLocal eq "yeah" ) {
					     $lovelymsg = $chkdmessage;
						 $hashin = substr(sha256_hex($lovelymsg),0,8);
						 $ttmsgcode = $ttmsgcode . "-" . $hashin;
						 $awesomessages{$ttmsgcode}{'hash'} = "$hashin";
						 $awesomessages{$ttmsgcode}{'content'} = decode_utf8($lovelymsg);
						 $awesomessages{$ttmsgcode}{'txrx'} = "tx"; 
						 $awesomessages{$ttmsgcode}{'timestamp'} = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
						 $awesomessages{$ttmsgcode}{'resentcount'} = 0;
						 $awesomessages{$ttmsgcode}{'isLocal'} = 1;
						 return;
					 }
						 
	}
	
	my $copyof = decode_utf8($lovelymsg);
	
	my $cryptc = '00';
	
	if ($keyidx ne '00' && $keyidx =~ m/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/ ) {
		
		if ( $dahfuckingkeys{$keyidx} && $dahfuckingkeys{$keyidx}{'pubK'} ) {
			
			my $encryptedpack = asymm_encrypt($keyidx,$lovelymsg);
			
			$lovelymsg = $encryptedpack if defined $encryptedpack;
			$cryptc = '03' if defined $encryptedpack;
			$cryptidx = $keyidx if defined $encryptedpack;
		}
		
	}else{
		$cryptidx = '000000';
	}
	
	$lovelymsg = compress($lovelymsg);
	
	
	if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {

		
	   my $cipher = Crypt::CBC->new(
		         {    
		           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
		
		          'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
		       #    'cipher'        => 'Camellia_PP',
		
		           'padding'       => 'standard',
		    
		        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
		         }
		        );
	
	
	$cipher->{'passphrase'} = $passphrase;
	$lovelymsg = $cipher->encrypt($lovelymsg);
	
	     if ( $cryptc eq '00' ) {
               $cryptc = '01';	
               $cryptidx = '000000';
            }else{
         if ( $cryptc eq '03' ) {
               $cryptc = '05';	
            } 
		}
    }
	
	$lovelymsg = encode_base64($lovelymsg,"");

	# "LIMA-UNIFORM-LIMA-ZULU" is the padding used in case you r using VOX function or so, and need to take care of the time needed to trigger it
	my $headerz = "LIMA-UNIFORM-LIMA-ZULU [BEGINCOMM]";
	$hashin = substr(sha256_hex($lovelymsg),0,8);
	my $pack = $headerz . $lovelymsg . "[cksum:$hashin:$ttmsgcode:$cryptc:$cryptidx][ENDCOMM]##END##";
	
	$ttmsgcode = $ttmsgcode . "-" . $hashin;

    my $msgarchive = $ttmsgcode . ":" . $pack;
    if (scalar(@messagessent) >= 15) {
		shift(@messagessent);
	}

    				     $awesomessages{$ttmsgcode}{'hash'} = "$hashin";
						 $awesomessages{$ttmsgcode}{'content'} = "$copyof";
						 $awesomessages{$ttmsgcode}{'pack'} = $pack;
						 $awesomessages{$ttmsgcode}{'txrx'} = "tx"; 
						 $awesomessages{$ttmsgcode}{'cryptc'} = $cryptc; 
						 if ( $cryptidx ne '000000' ) {
						 $awesomessages{$ttmsgcode}{'cryptidx'} = $cryptidx; 
					     }
						 $awesomessages{$ttmsgcode}{'timestamp'} = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
						 $awesomessages{$ttmsgcode}{'resentcount'} = 0;
    return ($pack);
  }
}


#########################
# check if resent

sub check_if_resent {
	
	if (@_) {
		   my $msgcode = join("",@_);
				if ($mustAsk2resend eq "yeahbaby") {
				
						if (@alreadyasked) {
							my $ifoundit;
							foreach (@alreadyasked) {
							   if ( $msgcode =~ m/$_/ ) {
						           $ifoundit = "yeah";
						       }else{

							   }
						     }
						     if ( !$ifoundit ) {
								   push(@askedresend,$msgcode);
								   push(@alreadyasked,$msgcode);
							   }
					      }else{
								   push(@askedresend,$msgcode); 
								   push(@alreadyasked,$msgcode);
							   
						  }
						  
						  
						  resenditpl0x();
					  }


   }
}


# decoding
##########################################

sub gettingdecodedmsg {
	
	    if (@_) {
	    my @tonOfShit;

		my $fullOfshit = join("",@_);
		$fullOfshit =~ s/\n//g ;
		my $headerz = "[BEGINCOMM]";
		my $hashin;
		my $wrapped = "nones";
		my $segment;
		
		my $doneAlready = "nones";
		
		my $msgcode;
		
		my $isEncrypted;
		
		@tonOfShit = split("##END##",$fullOfshit);

		for (my $i = 0 ; $i < scalar(@tonOfShit); $i++) {
		   
			
				if ($tonOfShit[$i] =~ m/\[BEGINCOMM\]/ ) {
				$wrapped = "yeah";
				$tonOfShit[$i] =~ s/^(.*)\[BEGINCOMM\]// ;
				$segment = "";
			     }
			

				if ($tonOfShit[$i] =~ m/\[ENDCOMM\]/ ) {
					
					if ($tonOfShit[$i] =~ m/\[cksum:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\]/ )
				 {
					 

					 $doneAlready = "nones";

		             my @revhashin = split("cksum:", $tonOfShit[$i]);
		             my @prehashin = split(":",$revhashin[1]);
		             
		             $hashin = $prehashin[0];
		             
		             $msgcode = $prehashin[1] . "-" . $prehashin[0];
		             
		             my $cryptc = $prehashin[2];
		             my $locatekey = $prehashin[3];
		             $locatekey = substr($locatekey,0,6);
		             
		             

		          if (!$msgcode) {
					   
				   }else{
					if ( $wrapped eq "yeah") { 
		             
					if ( $hashin && $msgcode && !$awesomessages{$msgcode} ) {
					
					
					$wrapped = "nones";
					my $final = $tonOfShit[$i];
					$final =~ s/\[ENDCOMM\](.*)$// ;
					$final =~ s/\[cksum:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\]// ;
					
					$segment = $segment . $final ;

					chomp($segment);
					my $probe = substr(sha256_hex($segment),0,8);

					if ($probe eq $hashin ) {

					if ( $segment =~ m/^U2FsdGVkX1/ ) {
						$isEncrypted = "yeah";
					}else{
						$isEncrypted = "nones";
					}
					
					
						$segment = decode_base64($segment);

		             if ( $isEncrypted eq "yeah" && ( $cryptc eq '01' || $cryptc eq '05' ) ) {			
						   my $cipher = Crypt::CBC->new(
			         {    
			           'key'           => 'b0ssjP3n1s+d2y0l0+IATTsuxiOB1vz7',      # change this to a decent key with 32 chars
			
		               'cipher'        => 'Rijndael',                              # defaults to AES but we suggest to use Camellia instead if possible, 
		                                                           # Camellia requires Crypt::Camellia or Crypt::Camellia_PP for the pure perl version
			       #    'cipher'        => 'Camellia_PP',
			
			           'padding'       => 'standard',
			    
			        #   'fuckNSA'       => 1,                                         # if you want to use the enforced Crypt::CBC features
			         }
			        );
		
		
		             $cipher->{'passphrase'} = $passphrase;

		             eval{$segment = $cipher->decrypt($segment)};
					             if ($@) {
						 print "error decrypting";

					 }else {
						 
					 }	     
				     
				     }	     

						 eval{$segment = uncompress($segment)};
						if ($@) {
						 print "error uncompressing";

					    }else {
						 
					     if ( $cryptc eq '03' || $cryptc eq '05' ) {			
							   
							   my $asymmdec_text = asymm_decrypt($locatekey, $segment) if defined $segment;
							   if ( $asymmdec_text ) {
							     $segment = $asymmdec_text ;
						       }else{
								 $segment = undef ;  
							   }
							   
						   }						 
						 
						 if ($segment) {
						    
						    $segment = Encode::decode_utf8($segment);
						    $segment =~ s/^:local/local/ ;
						 my ($isLocal,$ckdmsg) = check_for_commands($segment);

						 push(@newmessages,$segment);
						 $awesomessages{$msgcode}{'hash'} = "$probe";
						 $awesomessages{$msgcode}{'content'} = "$segment";
						 $awesomessages{$msgcode}{'txrx'} = "rx"; 
						 $awesomessages{$msgcode}{'timestamp'} = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
						 $awesomessages{$msgcode}{'resentcount'} = 0;
						 $awesomessages{$msgcode}{'cryptc'} = $cryptc; 
						 if ($isLocal) {
							 $awesomessages{$msgcode}{'isLocal'} = 1;
						 }

						 push(@donedecodedmsgs,$msgcode);
					      }
					 }

					}else{
						
						check_if_resent($msgcode);
				  
					}
					
				  	
				   }
				   # here	
			      }else{ 
			        
			       
			       check_if_resent($msgcode);
			       
			       }
			   }
				   
				}	 
				
					if ($wrapped eq "yeah" ) {

				$segment = $segment . $tonOfShit[$i];

			}
	
		}
				
		}    
		    if ($mustAsk2resend eq "yeahbaby") {
			resenditpl0x();
		}
			return(@newmessages);
   }
}

##########################################
#check if someone is asking to resend a msg that was received corrupted on the other end

sub check_resend_requests {
	    
	    if (@_) {
	    my @loggedshit;
	    
	    my @newmsgs;
	    
	    my $alreadydone = "nones";

		@loggedshit = @_;
		chomp(@loggedshit);
		my $gathershit = join("",@loggedshit);

		my @sortedshit = split("##END##",$gathershit);
		
		
		for (my $i = 0 ; $i < scalar(@sortedshit); $i++) {
	
			
			if ($sortedshit[$i] =~ m/\[PL0XRESNDMSG:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\]/ ) {
				my @loocode = split("PL0XRESNDMSG:",$sortedshit[$i],2);
				my $msgcode = substr($loocode[1],0,15);

				
			if ($msgcode) {			
				
			 if ( $awesomessages{$msgcode} && $awesomessages{$msgcode}{'pack'} && $awesomessages{$msgcode}{'resentcount'} <= 1  ) {
					push(@newmsgs,$awesomessages{$msgcode}{'pack'});
					my $newcount = ($awesomessages{$msgcode}{'resentcount'} + 1);
					$awesomessages{$msgcode}{'resentcount'} = $newcount;
				}
				
				
			 }
			}
	}  ## youz taking drugz again 
	   if (@newmsgs) {
		    	my	 $txstatus = main::get_tx_status();
	                                          	 while ($txstatus =~ m/tx/) {
                                        			 sleep(10);
	                                         		 $txstatus = main::get_tx_status();
	                                              	 }

        gogogodispatch(join("  ",@newmsgs));
	}
	
  }
}



##########################################

our $client;

our $term;
our $OUT = \*STDOUT;
our $debug;

our %methods;
our %commands;
our %encoders;

our %opts;

our $isconnected;


%encoders = ( "b" => \&RPC_BOOLEAN, "6" => \&RPC_BASE64,
	      "d" => \&RPC_DOUBLE, "s" => \&RPC_STRING );
	     
%opts = ( "c" => "", "d" => 0, "u" => "http://localhost:7362/RPC2" );

# create client
$client = RPC::XML::Client->new($fldigi_xmlrpc_server_url);


sub modem_setting {
	
	if (@_) {	 
	my $r;
	my ($tryit, $setfreq) = @_;
	req("modem.set_by_name", $tryit);	
    req("modem.set_carrier", $setfreq);
	return unless defined($r = req("main.get_afc"));
	if ($r->value eq 1) 
	{
		req("main.toggle_afc");
	}
    return unless defined($r = req("main.get_lock"));
	if ($r->value eq 0) 
	{
		req("main.toggle_lock");
	}

	return "penis";
	
   }
}

sub resenditpl0x {
	
	    if (@askedresend && scalar(@askedresend) >= 1) {	
	my @req2resend;
	foreach(@askedresend) {	
		chomp;	
	    my $rsndit = "LIMA-UNIFORM-LIMA-ZULU [PL0XRESNDMSG:$_]##END##";
	    push(@req2resend,$rsndit);
     }
     my $askq = join("  ",@req2resend);

			my $txstatus = main::get_tx_status();
		 while ($txstatus =~ m/tx/) {
			 sleep(10);
			 $txstatus = main::get_tx_status();
		 }
		 

	gogogodispatch($askq);
	@askedresend = ();
	return "penis";	
    }
	
}

sub send_line
{
    if (@_) {
	req("text.clear_tx");	
	req("text.add_tx_bytes", join(" ", @_));
	return "penis";
    }
}

sub sendthefuckout 
{
	req("main.run_macro", $macroTX);
	return "penis";
}

sub get_line_tx_timing {
	
	if (@_) {
	my $r;
  
    return unless defined($r = req("main.get_tx_timing",join(" ", @_)));
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    return($rctxt);
    }
}

sub get_tx_status {
	
    my $r;

    return unless defined($r = req("main.get_trx_status"));
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    return($rctxt);
    
	
}


sub get_recv_text
{
    my ($r, $len);

    return unless defined($r = req("text.get_rx_length"));
    return unless defined($r = req("text.get_rx", 0, $r->value));
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    $rctxt =~ s/\n//g;
    return($rctxt);
}

sub get_recv_last
{
    my ($rone, $r, $len);

    return unless defined($rone = req("text.get_rx_length"));
    return unless defined($r = req("text.get_rx", $lastcheck, $rone->value));
    $lastcheck = $rone->value;
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    $rctxt =~ s/\n//g;
    return($rctxt);
}

sub get_recv_last_rsndreq
{
    my ($rone, $r, $len);

    return unless defined($rone = req("text.get_rx_length"));
    return unless defined($r = req("text.get_rx", $lastcheckrsnd, $rone->value));
    $lastcheckrsnd = $rone->value;
    my $rctxt = $r->value;
    $rctxt =~ s/ //g;
    $rctxt =~ s/\n//g;
    return($rctxt);
}


sub encoderpc
{
    my $aref = $_[0];
    return unless (exists( $methods{$aref->[0]} ));

    my $sig = $methods{$aref->[0]}->[0]; $sig =~ s/.+://;
    my @args = split(//, $sig);

    # Try to find an encoder for each format string char.
    # Use it to encode the corresponding method argument.
    for (my $i = 0; $i <= $#args; $i++) {
	if (exists($encoders{$args[$i]}) && exists($aref->[$i])) {
	    print "Encoding arg " . ($i+1) . " as $args[$i]\n" if ($debug);
	    $aref->[$i+1] = &{ $encoders{$args[$i]} }($aref->[$i+1]);
	}
    }
}

sub req
{
    encoderpc(\@_);
    my $r = $client->send_request(@_);
    if (!ref($r)) {
	$r = undef;
	$isconnected = "nones";
    }
    elsif ($r->is_fault()) {
	print $OUT "Error " . $r->value->{"faultCode"} . ": " .
	           $r->value->{"faultString"} . "\n";
	$r = undef;
    $isconnected = "nones";	
    }else{
		$isconnected = "yeahbaby";
		}

    return $r;
}

sub decoderpc
{
    my $r;
    return "" unless defined($r = req(@_));
    return ref($r->value) ? Dumper($r->value) : $r->value;
}



sub build_cmds
{
    %methods = ();

    if (defined(my $r = req("fldigi.list"))) {
	foreach (@{$r->value}) {
	    $methods{ $_->{"name"} } = [ $_->{"signature"}, $_->{"help"} ];
	}

    }
}

# build commands hashes
build_cmds();

###########  sending to xmlrpc server

sub gogogodispatch {

  if (@_) {
	  
	my $r; 
	my $r2; 
	return unless defined($r = req("modem.get_name"));
	return unless defined($r2 = req("modem.get_carrier"));	
	if ($r->value ne "$currentmodem" || $r2->value ne "$frequencycarrier" ) 
	{
		
		modem_setting($currentmodem, $frequencycarrier);
	}

	  
           my $delivery = join("   ",@_);
           my $tadam = send_line($delivery) if defined $delivery;
           my $tutu = sendthefuckout() if defined $tadam;

           return ("Message Sent") if defined $tutu;

  }
}




###############################################################################

sub find_url {
   my $text = shift;
   if($text =~ /((ftp|http|https):\/\/[a-zA-Z0-9\/\\\:\?\%\.\,\&\;=#\-\_\!\+\~]*)/i){
	  return $1;
   }elsif($text =~ /(www\.[a-zA-Z0-9\/\\\:\?\%\.\,\&\;=#\-\_\!\+\~]*)/i){
	  return "http://".$1;
   }
   return undef;
}
 
sub fetch_rss {
	
	if (@_) {
		
		my @gofeeds = @_;

    my $ua = new LWP::UserAgent;
    $ua->agent("Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36");
    $ua->protocols_allowed( [ 'http','https'] );
    
    if ($mustUseProxy eq "useTor" ) {

    my $torproxy = 'socks://' . $torproxyhost . ':' . $torproxyport;
	$ENV{HTTPS_PROXY}              = "$torproxy"; 
	$ENV{HTTP_PROXY}               = "$torproxy";
    $ENV{CGI_HTTP_PROXY}           = "$torproxy";
	$ENV{CGI_HTTPS_PROXY}          = "$torproxy";
	$ua->env_proxy;
      } 
      
    if ($mustUseProxy eq "useProxy" ) {
	
	my $proxy = 'http://' . $proxyhost . ':' . $proxyport;
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
	$ENV{HTTPS_PROXY}               = "$proxy";
	$ENV{HTTP_PROXY}               = "$proxy";
	$ENV{CGI_HTTP_PROXY}            = "$proxy";
    $ENV{CGI_HTTPS_PROXY}           = "$proxy";
	
	if ($proxyuser && length($proxyuser) > 2 ) { 
	$ENV{HTTPS_PROXY_USERNAME}      = "$proxyuser";
	$ENV{HTTP_PROXY_USERNAME}      = "$proxyuser"; 
    }
	if ( $proxypass && length($proxypass) > 2) {
	$ENV{HTTP_PROXY_PASSWORD}      = "$proxypass"; 
    $ENV{HTTPS_PROXY_PASSWORD}      = "$proxypass";  
     }
     $ua->env_proxy;
	}
	
  
    
  my $got_url = $gofeeds[int rand($#gofeeds)];
  
  my $rss_url = find_url($got_url);
  
  
  return unless ($rss_url);

  my $request = HTTP::Request->new('GET', $rss_url);

  my $response = $ua->request ($request);
  
		 

  return unless ($response->is_success);
  

  my $source = $response->content;
    my $feed = XML::FeedPP->new( $source, -type => 'string');  

    my $wownews = "NEWS:\n\n";
    my $i = 0;
    foreach my $item ( $feed->get_item() ) {
        if ($i <= 6) {
         $wownews = $wownews . $item->title() . "\n\n";
        }
        $i++
    }

          return($wownews);
   }
}

###############################################################################
 my $rcved_msgs;
 my $txwarning;
 my $timercheckresend = 0;
 my $timernews = 0;
 my $timercommunity = 0;
 my $timertwitter = 0;
 
 my $timersavemsg = 0;
 
 my $timerRoutes = 0;
 
sub get_last_msgs {
   
     my $checkmsgs = main::get_recv_text();
     my $donusdone = main::gettingdecodedmsg($checkmsgs) if defined $checkmsgs;
     
     $currentlogtxt = "";
	 $currentlogtxt = $currentlogtxt . "Content-type: text/plain\n\n";
     $currentlogtxt = $currentlogtxt . "######################################################\n";
     $currentlogtxt = $currentlogtxt . "###    MESSAGES LOG on ";
	 my $logdate = POSIX::strftime "%a %b %e %H:%M:%S %Y    ###\n",localtime;
     $currentlogtxt = $currentlogtxt .  $logdate;  
     $currentlogtxt = $currentlogtxt . "######################################################";
     $currentlogtxt = $currentlogtxt . "\n\n================================================================"; 
		
	my $timenow = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
	$currentmessages = "";	
   foreach my $message (sort { $awesomessages{$b}{'timestamp'} <=> $awesomessages{$a}{'timestamp'} } keys %awesomessages) {

   
   if (int($timenow - $awesomessages{$message}{'timestamp'})  >= 3600 )
   {
	   $awesomessages{$message}{'pack'} = undef;
   }
   
   my $cryptlabel = ' ';
   my $sentto = "\n";
   if ($awesomessages{$message}{'cryptc'} && $awesomessages{$message}{'cryptc'} eq '01' ) {
	   $cryptlabel = '  [Encrypted AES-256]';
   }
   if ($awesomessages{$message}{'cryptc'} && $awesomessages{$message}{'cryptc'} eq '03' ) {
	   $cryptlabel = '  [Encrypted RSA-2048/AES-256]';
   }
   if ($awesomessages{$message}{'cryptc'} && $awesomessages{$message}{'cryptc'} eq '05' ) {
	   $cryptlabel = '  [Encrypted AES-256] + [Encrypted RSA-2048/AES-256]';
   }
   if ($awesomessages{$message}{'cryptidx'} && $awesomessages{$message}{'cryptidx'} ne '000000' && length($awesomessages{$message}{'cryptidx'}) > 4 ) {
	   
	   my $idxc = $awesomessages{$message}{'cryptidx'} ;
	   if ( $dahfuckingkeys{$idxc}{'name'} && length($dahfuckingkeys{$idxc}{'name'}) >= 1 ) {
		   $sentto = "\nSENT-TO : " . $dahfuckingkeys{$idxc}{'name'} . "\n\n";
	   }
	  
   }
   
   my $datee = localtime($awesomessages{$message}{'timestamp'});
   my $messagecontent = main::encode_utf8($awesomessages{$message}{'content'});
   my $domb = "\n\nMESSAGE CODE: " . $message . $cryptlabel . "\n\n\n" . $sentto . $messagecontent . 
   "\n\n\n\n\n\n" . $datee ;
   my $edomb = HTML::Entities::encode_entities_numeric($domb, '<>&"');
  
   
   if ( $awesomessages{$message}{'isLocal'} ) {
	   $currentmessages = $currentmessages . "<div id='localmsg'><code><pre>\n\nLOCAL MESSAGE:$edomb</pre></code></div>";
	   $currentlogtxt = $currentlogtxt . "\n\nLOCAL MESSAGE:$domb";
   }else{
   
   if ($awesomessages{$message}{'txrx'} eq "tx") {
	       $currentmessages = $currentmessages . "<div id='sent'><code><pre>$edomb - Sent</pre></code></div>";
	       $currentlogtxt = $currentlogtxt . "$domb - Sent";
	   }else{
            $currentmessages = $currentmessages . "<div id='received'><code><pre>$edomb - Received</pre></code></div>";
            $currentlogtxt = $currentlogtxt . "$domb - Received";
     }
 }
     $currentmessages = $currentmessages . "----------------------------------------------------------------";
     $currentlogtxt = $currentlogtxt . "\n\n----------------------------------------------------------------";
    }	
			    
		return;
		
}

sub refresh_last_msgs {
	
	
			 if ( ($txwarning && $txwarning =~ m/fldigi is not running currently/i ) || !%methods ) {


			 	 main::build_cmds();
	             main::modem_setting($currentmodem, $frequencycarrier) if %methods;
		 }
		
	eval{$rcved_msgs = get_last_msgs()};
	
		if ($mustAnswerResendreq eq "yeahbaby") {
		 if ($timercheckresend > 4) {
			 my $pack;
     	     $pack = main::get_recv_last_rsndreq();
			 main::check_resend_requests($pack) if defined $pack;
			 $timercheckresend = 0;
			 }
		$timercheckresend++;	
	} 
	
	   if ($mustNewsBroadcast eq "yeahcool") {
		 if ($timernews >= 1) {
	     if ($checknews eq "yeah") {
			my $feedresults = main::fetch_rss(@rssfeeds);
			 my $postnews = main::sendingshits('00',$feedresults) if defined $feedresults;
		     my $mega = main::gogogodispatch($postnews) if defined $postnews;
			 $checknews = "nones";
			 $timernews = 0;
		 }
	    }
	    $timernews++;
       } 
       
       if ($mustCommunityBroadcast eq "yeahcool") {
		 if ($timercommunity >= 1) {
	     if ($checkcommunity eq "yeah") {
			 my $feedresults = main::fetch_rss(@communityfeeds);
			 my $postnews = main::sendingshits('00',$feedresults) if defined $feedresults;
		     my $mega = main::gogogodispatch($postnews) if defined $postnews;
			 $checkcommunity = "nones";
			 $timercommunity = 0;
		 }
	    }
	    $timercommunity++;
       } 

       if ($mustTweetBroadcast eq "yeahcool") {
		 if ($timertwitter >= 1) {
	     if ($checktwitter eq "yeah") {	
			 my $twtresults;
			 if ( $searchtwtterm ) {
				  $twtresults = main::twitter_searching($searchtwtterm);
				  $twtresults =~ s/^:/_/ ;
			  }else{
				   $twtresults = main::twitter_searching();
				   $twtresults =~ s/^:/_/ ;
			   }	     
			 my $posttweets = main::sendingshits('00',$twtresults) if defined $twtresults;
		     my $mega = main::gogogodispatch($posttweets) if defined $posttweets;
			 $checktwitter = "nones";
			 $timertwitter = 0;
		 }
	    }
	    $timertwitter++;
       }
       
       	if ($timersavemsg > 0) {

              main::save_messages();
			 $timersavemsg = 0;

	    }
	    $timersavemsg++;
	
        if ($buildRoutes eq "yeah") {
	    if ($timerRoutes > 0) {
 	          my $checklaststuff = main::get_recv_last();

              my $pass1 = main::announce_list();
              my $pass2;
              my $pass3;
              if ($checklaststuff) {
              $pass2 = main::receive_announce($checklaststuff);# if defined $pass1;
              $pass3 = main::build_list($checklaststuff) if defined $pass2;
		      }
              #
              if ($pass2  && length($pass2) > 6 && $pass1 && length($pass1) > 6 ) {
              my $postitall = $pass1 . "  " . $pass2;
              main::gogogodispatch($postitall) if defined $postitall;
		      }
			 $timerRoutes = 0;

	      }
	    $timerRoutes++;
	    }
	#####
	
	
	######
	
	
	
}

##############################################################################

 {
 package ZonkeyServer;
 
 #use HTTP::Server::Simple::CGI;  #in case you went mad installing Net::Server module, and you need just a single threaded session etc...
 use HTTP::Server::Simple::CGI::PreFork;
 use HTML::Entities;
 use base qw(HTTP::Server::Simple::CGI);
 use Time::HiRes qw ( setitimer ITIMER_VIRTUAL time );


    
 my $style2use = qq{<link rel="stylesheet" type="text/css" href='style.cssv1'>};

 my $style = qq{

  \@font-face \{
      font-family: 'droid_sansregular';
      src: url('droidsans-webfont.eot');
    \}

  \@font-face \{
      font-family: 'droid_sansregular';
      src: url(data:application/x-font-woff;charset=utf-8;base64,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) format('woff'),
      url('droidsans-webfont.ttf') format('truetype');
      font-weight: bolder;
      font-style: normal;
    \}
	
	body      \{
                font-family : 'droid_sansregular';
			    background-color:#ffffff;
			  \}
			
  	p .content  \{
                font-family : 'droid_sansregular';
                max-width : 100px;
			  \}
							
							
	#logo     \{
			    height: 150px;
                width: 800px;
			    background-repeat: no-repeat;
			    background-image: url(data:image/png;base64,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);
			  \}
							
							
	a:link \{color: blue; text-decoration: underline; \}
    a:active \{color: blue; text-decoration: underline; \}
    a:visited \{color: blue; text-decoration: underline; \}
    a:hover \{color: blue; text-decoration: none; \}
	
    #button  \{
    border: none;
	outline: none;
    height: 53;
    width: 175;
	cursor:pointer;
	background:none;
	background-repeat: no-repeat;
	background-image: url("data:image/png;base64,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");
\}
    #button:hover \{
    border: none;
	outline: none;
	height: 53;
    width: 175;
	cursor:pointer;
	background:none;
	background-repeat: no-repeat;
	background-image: url("data:image/png;base64,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");
\}	
	input, select, textarea \{
	            background-repeat: no-repeat;
				font-family : 'droid_sansregular';
				border-width: 4px;
				border-radius:0 10px 10px 10px;
                border-style: solid;
                border-color: #1E90FF;
				font-size   : 100%;
              \}
              
    code      \{
                font-family : 'droid_sansregular';
                font-size   : 14px;
              \}
              
    #smallf   \{
                font-family : 'droid_sansregular';
                font-size   : 85%;
              \}
              
    #xsmallf  \{
                font-family : 'droid_sansregular';
                font-size   : 75%;
              \}
							
	#localnow \{
				color : green;
				font-family : 'droid_sansregular';
				font-size : 16px;
			  \}
			
	#attention\{
				color : red;
				font-family : 'droid_sansregular';
				font-size : 14px;
			  \}
			
	#logfrom  \{
				color : gray;
				font-family : 'droid_sansregular';
				font-size : 12px;
			  \}
			
	#restart  \{
				color : gray;
				font-family : 'droid_sansregular';
				font-size : 12px;
			  \}
			
	#wait     \{
				color : red;
				font-family : 'droid_sansregular';
				font-size : 12px;
			  \}
			
	#isReady  \{
				color : green;
				font-family : 'droid_sansregular';
				font-size : 16px;
			  \}
			
	#localmsg \{
				color : blue;
				font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	#sent     \{
				color : red;
				font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	#received \{
                font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	#transmitting \{
                color : blue;
                font-family : 'droid_sansregular';
				font-size : 15px;
			  \}
			
	.greentxt \{
				font-family : 'droid_sansregular';
                color : green;
			  \}
					
 };
 
 
 my $favicon = qq{<link href='data:image/x-icon;base64,AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAAAAAAAAAAAAAAEAAAAAAAAADmhxgAAAAAAOaGFgDxvoIA54sfAPro0gDqmjsA99i0AOePJgDmhxcA9MmXAO+0bgDrn0UAAAAAAAAAAAAAAAAAERERERERERERERERERERERERFVd1URERERFaO7OlERERFavGbLpRERFatoRIa6UREVPICZCMNRERe2SSKUa3ERF7ZJIpRrcREVPICZCMNRERWraESGulEREVq8ZsulERERFaO7OlERERERVXdVERERERERERERERERERERERERH//wAA//8AAPgfAADwDwAA4AcAAMADAADAAwAAwAMAAMADAADAAwAAwAMAAOAHAADwDwAA+B8AAP//AAD//wAA' rel="icon" type="image/x-icon" />};
 my $headerz = qq{Content-type: text/html; charset=UTF-8

    <html><title>Free Communications Over The Air</title><head>$favicon $style2use</head><body>};

 my $headerzmsg = qq{Content-type: text/html; charset=UTF-8

           <html><title>Free Communications Over The Air</title><head><meta http-equiv="refresh" content="30" >$favicon $style2use</head><body>};

my $ergumlogos = qq{<div id='logo'></div>};
 my $footerz = '</br></br></br></br></br></br></br></br><code><p>2017. ZonkeyNet. Emergency Mesh Radio Network. </p></code></body></html>';
 
 my %dispatch = (
     '/' => \&msg_basic,
   #  '/advanced' => \&msg_advanced,  # this wasn't revisited lately, enable it and check it if you want 
     '/xtras' => \&msg_xtras,
     '/reconn' => \&tryreconnectfldigi,
     '/log.txt' => \&gimmelog,
     '/settings' => \&zonkey_settings,
     '/addKey'    => \&add_buddy_key,
      '/delKey'    => \&del_buddy_key,
      '/publicKey.pem' => \&get_my_publickey,
      '/About'     => \&about_and_shits,
      '/crypt'     => \&msg_crypt,
      '/style.cssv1' => \&load_css,
      '/tables' => \&show_tables,
     # ...
 );
 
 sub load_css {
	 
	print qq{$style};
 }
 

 
 sub handle_request {
     my $self = shift;
     my $cgi  = shift;
   
     my $path = $cgi->path_info();
     my $handler = $dispatch{$path};
 
     if (ref($handler) eq "CODE") {
         print "HTTP/1.0 200 OK\r\n";
         $handler->($cgi);
         
     } else {
         print "HTTP/1.0 404 Not found\r\n";
         print $cgi->header,
               $cgi->start_html('Not found'),
               $cgi->h1('Not found'),
               $cgi->end_html;
     }
 }



 
 my $penispenis = " ";
 
 
 sub tryreconnectfldigi {

	 main::build_cmds();
	 main::modem_setting($currentmodem, $frequencycarrier);

    print qq{$headerz};


	     my $txstatus;
	     eval{$txstatus = main::get_tx_status()};
		if (defined $txstatus) {
			
					  print qq{<p>current fldigi status:  $txstatus . Fldigi looks fine, you can go back to default interface.</p></br></br></br>}; 
					  print qq{<a href="/">Go Back to the Messages</a>};			
				}else {
                     print qq{<p>Didn't work, verify fldigi is up and running and retry later </p>};
					 }	   
	print qq{</br></br></br></br></br>};
	print qq{$footerz};
	 
 }
 

 
 sub msg_basic {
     my $cgi  = shift;  
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 

     my $penis;

     my $pack2send= " ";
     my $letstest;
     my $txstatus;
     my $mybord;
     
		 $txstatus = main::get_tx_status();
		 if (!$txstatus || !%methods) {
			 $txwarning = "\n\n<div id='attention'>ATTENTION: fldigi is not running currently.</div>\n\n<div id='localnow'>Only Local Messages available. </div>\n\n<div id='logfrom'>please start fldigi if you want to transmit to the Air.</div>";
		 }
		 elsif ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

		 }elsif ($txstatus =~ m/rx/){
			  $txwarning = "<div id='isReady'>READY TO SEND.</div>\n<div id='logfrom' >Logged In from $usedIp.</div>";

		 }
		 
		 
		 if (!$txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 1 ) {
			 
			 eval{$penis = $cgi->param('postfield')};
			 if ($penis =~ m/^:local/ ) {
			 
		     }else {
				 $penis = ":local" . $penis;
			 }
			 main::sendingshits('00',$penis) if defined $penis;
			 main::get_last_msgs();
			 
		 }
		 
         if ($txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 3 && $cgi->param('postfield') ne $penispenis) {
		 eval{$penis = $cgi->param('postfield')};
		 eval{$penispenis = $cgi->param('postfield')};
		 if ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
		 }else{
          
		 $pack2send = main::sendingshits('00',$penis) if defined $penis;
		 $letstest = main::get_line_tx_timing($pack2send) if defined $pack2send;
         
         if ($letstest) {
		 my @shit = split(":",$letstest);
		 $mybord = int($shit[2] + 0.5);
	     }
		 
		 my $mega = main::gogogodispatch($pack2send) if defined $pack2send;
		 $penis =Encode::decode_utf8($penis);
		 		 $penis = HTML::Entities::encode_entities($penis);

         $txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
         
         main::get_last_msgs();
	      }
	      
	   }else{
		 
		 }
		 
     print qq{$headerzmsg};
     print qq {<p style="text-align:right;font-size:14px;"><a href="/About" ><img src="data:image/png;base64,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" title="Info" border="0" width="60" height="60"></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/log.txt" ><img src="data:image/png;base64,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" title="Log Messaggi" border="0" width="60" height="60"></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/publicKey.pem" ><img src="data:image/png;base64,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" title="My Public Key" border="0" width="60" height="60"></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/crypt" ><img src="data:image/png;base64,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" title="Messaggio Criptato" border="0" width="60" height="60"></a>};
     
     if ($usedIp eq "127.0.0.1") {
 		 print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/settings" ><img src="data:image/png;base64,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" title="Impostazioni" border="0"  width="65" height="65"></a>};
	 };
	 print qq {</p></br>};
	 
	 print qq{$ergumlogos};
	 print qq{<table><tr><form name="formMessage" method="POST" >

    <textarea name="postfield" rows="6" cols="120" placeholder="Post a Message Here (280 caratteri max)" maxlength=280 ></textarea></br></tr>
    <tr><button type="submit" style="height: 53px; width: 175px" id="button">};
    
    
    
    #####################

    #######################
    
    
    print qq{</form></tr></table>};
    if ($mybord) {
    print qq{<code></br></br><div id='transmitting' >Transmitting...  $mybord seconds to transmit your last message</div></br></code>};
    }
    if ($txstatus && $penis) {
       print qq{<code>TRANSMITTING MESSAGE:</br></br><pre>$penis</pre></br></code>}; 
    }
    if ($txwarning) {
		print qq{<code></br></br><pre>$txwarning </pre></br></code>};
	}else{

	}
        
    print qq{</br>------------------------ Last  Messages ------------------------ </br>};


	if ($currentmessages) {
	print qq{$currentmessages};
    }else{
	print qq{<p>No Messages Yet.</p>};	
	}
	
	print qq{$footerz};

}
	 
	
sub msg_crypt {
     my $cgi  = shift;   
     return if !ref $cgi;
       
     my $usedIp = $cgi->remote_host(); 

     my $penis;
     my $pack2send= " ";
     my $letstest;
     my $txstatus;
     my $mybord;

		 $txstatus = main::get_tx_status();
		 if (!$txstatus || !%methods) {
			 $txwarning = "\n\n<div id='attention'>ATTENTION: fldigi is not running currently.</div>\n\n<div id='localnow'>Only Local Messages available. </div>\n\n<div id='logfrom'>please start fldigi if you want to transmit to the Air.</div>";
		 }
		 elsif ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

		 }elsif ($txstatus =~ m/rx/){
			  $txwarning = "<div id='isReady'>READY TO SEND.</div>\n<div id='logfrom' >Logged In from $usedIp.</div>";

		 }
		 
		 
		 if (!$txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 1 ) {
			 
			 eval{$penis = $cgi->param('postfield')};
			 if ($penis =~ m/^:local/ ) {
			 
		     }else {
				 $penis = ":local" . $penis;
			 }
			 main::sendingshits('00',$penis) if defined $penis;
			 main::get_last_msgs();
			 
		 }
		 
        if ($txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 3 && $cgi->param('postfield') ne $penispenis) {
		 eval{$penis = $cgi->param('postfield')};
		 eval{$penispenis = $cgi->param('postfield')};

		 if ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
		 }else{
			 
			 
		################	 
		
		my $usekeyidx;
		
		if ($cgi->param('pubkeys') && length($cgi->param('pubkeys')) > 1 && $cgi->param('pubkeys') ne 'none' ) { 
			 	  
	     $usekeyidx = $cgi->param('pubkeys') ;
	      
        }
	 
	    #################### 
          
         if ( $usekeyidx ) {
   
		 $pack2send = main::sendingshits($usekeyidx,$penis) if defined $penis;
		 
	     }else{
			$pack2send = main::sendingshits('00',$penis) if defined $penis; 
		 }
		 $letstest = main::get_line_tx_timing($pack2send) if defined $pack2send;
         
         if ($letstest) {
		 my @shit = split(":",$letstest);
		
		 $mybord = int($shit[2] + 0.5);
	     }
		 
		 my $mega = main::gogogodispatch($pack2send) if defined $pack2send;
		 $penis =Encode::decode_utf8($penis);
		 		 $penis = HTML::Entities::encode_entities($penis);


         $txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
         
         main::get_last_msgs();
	 
	     }
	
	 }else{

		 }

     print qq{$headerzmsg};
     
     print qq {<p style="text-align:right;font-size:14px;"><a href="/About" ><img src="data:image/png;base64,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" border="0" title="Info" width="60" height="60"></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/log.txt" ><img src="data:image/png;base64,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" title="Log Messaggi" border="0" width="60" height="60"></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/publicKey.pem" ><img src="data:image/png;base64,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" title="My Public Key" border="0" width="60" height="60"></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/" ><img src="data:image/png;base64,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" title="Messaggio Semplice" border="0" width="65" height="65"></a>};
     if ($usedIp eq "127.0.0.1") {
 		 print qq {&nbsp;&nbsp;&nbsp;&nbsp;<a href="/settings" ><img src="data:image/png;base64,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" title="Impostazioni" border="0" width="65" height="65"></a>};
	 };
	 print qq {</p></br>};
	 
	 print qq{$ergumlogos};
	 print qq{<table><tr><form name="formMessage" method="POST" >

    <textarea name="postfield" rows="6" cols="120" placeholder="Post A Message Here (280 characters max)" maxlength=280 ></textarea></br></tr>
    <tr><input type="submit" value="" id="button" style="height: 53px; width: 175px" >};
   
    #####################
    
     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Encrypt Message to : <select name="pubkeys" >};
  
     print qq{<option size="15" value="none" >None (Do No Encrypt this time)</option>};
      foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( !$dahfuckingkeys{$publickey}{'Local'} ) {
		  
		  my $name = HTML::Entities::encode_entities_numeric($dahfuckingkeys{$publickey}{'name'}, '<>&"');
		  my $kcode = HTML::Entities::encode_entities_numeric($publickey, '<>&"');
	  
		  print qq{<option size="15" value="$kcode" >$name</option>};

	   }
		  
	  }
     print qq{</select>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="/addKey" ><code><img src="data:image/png;base64,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" border="0" width="50" height="50" vspace="20" align="center" title="Aggiungi Chiave RSA"></code></a>};
    
    #######################
    
    
     print qq{</form></tr></table>};
      if ($mybord) {
        print qq{<code></br></br><div id='transmitting' >Transmitting...  $mybord seconds to transmit your last message</div></br></code>};
       }
      if ($txstatus && $penis) {
        print qq{<code>TRANSMITTING MESSAGE:</br></br><pre>$penis</pre></br></code>}; 
       }
      if ($txwarning) {
		print qq{<code></br></br><pre>$txwarning </pre></br></code>};
	  }else{

	  }
     print qq{</br>------------------------ Last  Messages ------------------------ </br>};

                         

	
	if ($currentmessages) {
	print qq{$currentmessages};
    }else{
	print qq{<p>No Messages Yet.</p>};	
	}
	
	print qq{$footerz};
	

}
	
	
	
## this one wasn't re-visited lately. probably to be left out later	
sub msg_advanced {
     my $cgi  = shift;   
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 
     
     if ($usedIp eq "127.0.0.1") {

     my $penis = " ";
     my $pack2send= " ";
     my $letstest;
     my $txstatus;
     my $mybord;
     
     my $changemodemsettings;
     
     my $modifiedoptions;

		 $txstatus = main::get_tx_status();
		 if (!$txstatus) {
			 $txwarning = "\n\n<div id='attention'>ATENTION: fldigi is not running currently.</div>\n\n<div id='localnow'>Only Local Messages available. </div>\n\n<div id='restart'>please start fldigi if you want to transmit to the Air.</div>";
		 }
		 elsif ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

		 }else {
			  $txwarning = "<div id='isReady'>READY TO SEND.</div>\n<div id='logfrom' >Logged In from $usedIp.</div>";

		 }
		 
		 
		 if (!$txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 1 ) {
			 
			 eval{$penis = $cgi->param('postfield')};
			 $penis = ":local" . $penis;
			 main::sendingshits('00',$penis) if defined $penis;
			 
		 }
		 
		 
     if ($txstatus && $cgi->param('postfield') && length($cgi->param('postfield')) > 3 && $cgi->param('postfield') ne $penispenis) {
		 eval{$penis = $cgi->param('postfield')};
		 eval{$penispenis = $cgi->param('postfield')};

		 $txstatus = main::get_tx_status();

		 if ($txstatus =~ m/tx/) {
			$txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";
		 }else{
			 
		 if ($cgi->param('encryption') && $cgi->param('encryption') eq "encrypt") {
			 if ($mustEncrypt eq "nones") {
			 $mustEncrypt = "yeahbabygetthisoneintoyourassFCCandNSA";
			 $modifiedoptions = "yeah";
		 }
			 if ($cgi->param('passphrase') ne $passphrase) {
				
			      $passphrase = $cgi->param('passphrase');
			      $modifiedoptions = "yeah";
			      
		      }
			 }else{
				 if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
				 $mustEncrypt = "nones";
				 $modifiedoptions = "yeah";
			 }
				 }
		 
		 if ($cgi->param('modes') ne $currentmodem) {
			 $currentmodem = $cgi->param('modes');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
		 
		 if ($cgi->param('freqcursor') ne $frequencycarrier) {
			 $frequencycarrier = $cgi->param('freqcursor');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
			 

		
		if ($cgi->param('answer2resend') && $cgi->param('answer2resend') eq "answresend" ) {
			
			if ($mustAnswerResendreq eq "nones" ) {
			$mustAnswerResendreq = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ($mustAnswerResendreq eq "yeahbaby" ) {
			$mustAnswerResendreq = "nones";
			$modifiedoptions = "yeah";
		   }

		}
		if ($cgi->param('askresend') && $cgi->param('askresend') eq "askresend" ) {
			if ( $mustAsk2resend eq "nones" ) {
			$mustAsk2resend = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ( $mustAsk2resend eq "yeahbaby" ) {
			$mustAsk2resend = "nones";
			$modifiedoptions = "yeah";
		   }
		}

        if ($changemodemsettings || $modifiedoptions )
        {
			main::save_settings();
			undef $modifiedoptions;
		}
        

		if ($changemodemsettings && $changemodemsettings eq "yeah") {
			main::modem_setting($currentmodem, $frequencycarrier);
			undef $changemodemsettings;
		}


		


		 $pack2send = main::sendingshits('00',$penis) if defined $penis;
		 $letstest = main::get_line_tx_timing($pack2send) if defined $pack2send;
         
         if ($letstest) {
		 my @shit = split(":",$letstest);
		 $mybord = int($shit[2] + 0.5);
	     }
		 
		 my $mega = main::gogogodispatch($pack2send) if defined $pack2send;
		 $penis =Encode::decode_utf8($penis);
		 		 $penis = HTML::Entities::encode_entities($penis);

        $txwarning = "<div id='wait'>Please wait a few seconds to post a new message, the System is currently busy transmitting data.</div>";

	      }

	 }else{


     my  $epassphrase = HTML::Entities::encode_entities_numeric($passphrase, '<>&"') if defined $passphrase; 
     my  $ecallsign = HTML::Entities::encode_entities($callsign) if defined $callsign;
    
     my  $efrequencycarrier = HTML::Entities::encode_entities($frequencycarrier);

     print qq{$headerzmsg};
	 print qq{$ergumlogos};

	 print qq{<table><tr><form name="formMessage" method="POST" >

    <textarea name="postfield" rows="6" cols="120" placeholder="Post A Message Here (280 characters max)" maxlength=280 ></textarea></br></tr>
    <tr><td><input type="submit" value="" id=button style="height: 53px; width: 175px" >};
    if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" checked>};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" >};
			}
			print qq{ Encrypt Message with Passphrase: <input name="passphrase" maxlength=140 placeholder="Post A Message Here (140 characters max)" value="$epassphrase" size=36></td></tr>
   <tr><td><div id='smallf'> Data Transmission Mode: <select name="modes">
  <option value="$currentmodem" selected>$currentmodem</option>
  <option disabled>---</option>
  <option value="BPSK31">BPSK31</option>
  <option value="QPSK31">QPSK31</option>
  <option value="QPSK250">QPSK250</option>
  <option value="QPSK500">QPSK500</option>
  <option value="PSK500R">PSK500R</option>  
  <option value="PSK1000R">PSK1000R</option>
  <option value="MFSK64">MFSK64-Image</option>  
  <option value="MFSK128">MFSK128-Image</option>  

 <option value="PSK63RC5">PSK63RC5</option>
<option value="PSK63RC10">PSK63RC10</option>
<option value="PSK63RC20">PSK63RC20</option>
<option value="PSK63RC32">PSK63RC32</option>
<option value="PSK125RC12">PSK125RC12</option>
<option value="PSK125RC16">PSK125RC16</option>
</select> &nbsp;&nbsp;&nbsp;&nbsp;Carrier Frequency center:<input name="freqcursor" maxlength=4 value="$efrequencycarrier" size="4"></div></td></tr><tr><td><div id='smallf'>Automatically:&nbsp;&nbsp;};

      if ( $mustAsk2resend eq "yeahbaby") {
	    print qq{<input type="checkbox" name="askresend" value="askresend" checked>};
	  }else{
		print qq{<input type="checkbox" name="askresend" value="askresend" >};
		}
	 print qq{Ask others to resend messages when I received them corrupted&nbsp;&nbsp;&nbsp;&nbsp;  };
	
      if ( $mustAnswerResendreq eq "yeahbaby" ) {
	    print qq{<input type="checkbox" name="answer2resend" value="answresend" checked>};
	  }else {
		print qq{<input type="checkbox" name="answer2resend" value="answresend" >};
		}
		
	 print qq{Answer requests from others to resend messages</div></td></tr><tr><td><div id='xsmallf'>(resending back and forth can be annoying, use it only when needed)</div></td> </form></tr></table>};
      if ($mybord) {
        print qq{<code></br></br>Transmitting...  $mybord seconds to transmit your last message</br></code>};
       }
      if ($txstatus && $penis) {
        print qq{<code>TRANSMITTING MESSAGE:</br></br><pre>$penis</pre></br></code>}; 
      }
      if ($txwarning) {
		print qq{<code></br></br><pre>$txwarning</pre></br></code>};
	  }else{
	  }
     print qq{</br>------------------------ Last  Messages ------------------------ </br>};

     if ($currentmessages) {
	    print qq{$currentmessages};
      }else{
	    print qq{<p>No Messages Yet.</p>};	
	  }
	
	 print qq{$footerz};
       }
   }
}
	 
	 
sub msg_xtras {
	
     my $cgi  = shift;  
     return if !ref $cgi;
       
     print qq{$headerz};
	 print qq{$ergumlogos};
   
    	 my $sentmsgs;
		 
		 
     print qq{<p>--- Recently Transmitted Packets ---</p></br></br>};		 
     print qq{<code><pre>};		 
     
		    foreach my $message (sort { $awesomessages{$b}{'timestamp'} <=> $awesomessages{$a}{'timestamp'} } keys %awesomessages) {
             if ( $awesomessages{$message}{'pack'} && length($awesomessages{$message}{'pack'}) > 10 )
                   {
					  $sentmsgs = $awesomessages{$message}{'pack'} ;
					  $sentmsgs = HTML::Entities::encode_entities($sentmsgs);
					  
					  print qq{</br></br>---------------------------------------------------</br></br>};
                   }
              }
    
     print qq{</pre></code>};
     print qq{</br></br></br></br></br></br>$footerz};
     
     
 }
 
sub gimmelog {
	 
	 if ($currentlogtxt) {
		print $currentlogtxt;
		 }
		 
 }
 
sub zonkey_settings {
	
     my $cgi  = shift;  
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 
     
     if ($usedIp eq "127.0.0.1") {

     my $reload;
     my $changemodemsettings;
     my $modifiedoptions;
    
     if ($cgi->param('doitdoit') && $cgi->param('doitdoit') eq "Save Preferences" ) {

	 	if ($cgi->param('mustListenAll') && $cgi->param('mustListenAll') eq "yeahyeah" && $mustListenAllInterfaces eq "nones") {
		 $mustListenAllInterfaces = "yeah";
		 $pid->host('0.0.0.0');
		 #$pid->run();
		 $pid->run(prefork => 1);
		 # more elegant solution?
         
          }
         if ($cgi->param('mustListenAll') && $cgi->param('mustListenAll') ne "yeahyeah" && $mustListenAllInterfaces eq "yeah") {
		 $mustListenAllInterfaces = "nones";
		 $pid->host('127.0.0.1');
		 #$pid->run();
		 $pid->run(prefork => 1);
		
          }
	 
	 	    if ($cgi->param('mustUseProxy') eq "direct") {
		 $mustUseProxy = "nones";
	     }
	 	 if ($cgi->param('mustUseProxy') eq "useTor") {
		 $mustUseProxy = "useTor";
		    if ($cgi->param('torproxyhost') && $cgi->param('torproxyhost') =~ /(^\d+\.\d+\.\d+\.\d+$)/ ) {
	
				$torproxyhost = $cgi->param('torproxyhost');
			}	 
		 	if ($cgi->param('torproxyport') && $cgi->param('torproxyport') =~ /(^\d+$)/ ) {
	
				$torproxyport = $cgi->param('torproxyport');
			}	
	     }
	     if ($cgi->param('mustUseProxy') eq "useProxy") {
		 $mustUseProxy = "useProxy";
		 	if ($cgi->param('proxyhost') && $cgi->param('proxyhost') =~ /(^\d+\.\d+\.\d+\.\d+$)/ ) {
	
				$proxyhost = $cgi->param('proxyhost');
			}	 
		 	if ($cgi->param('proxyport') && $cgi->param('proxyport') =~ /(^\d+$)/ ) {
	
				$proxyport = $cgi->param('proxyport');
			}	
		 	if ($cgi->param('proxyuser') && length($cgi->param('proxyuser')) > 2 ) {
	
				$proxyuser = $cgi->param('proxyuser');
			}else{
				undef $proxyuser;
			}	
			if ($cgi->param('proxypass') && length($cgi->param('proxypass')) > 2 ) {
	
				$proxypass = $cgi->param('proxypass');
			}else{
				undef $proxypass;
			}		

	     }
	 
	    if ($cgi->param('mustNewsBroad') && $cgi->param('mustNewsBroad') eq "gimmeNews") {
		 $mustNewsBroadcast = "yeahcool";

	 }else{
		 $mustNewsBroadcast = "nones";

	 }
	 
   ########## twitter ##############
	 
	 	if ($cgi->param('mustTweet') && $cgi->param('mustTweet') eq "beCoolAndTweet" ) {
		 $mustTweetOthers = "yeahcool";
	 }else{
		 $mustTweetOthers = "nones";
	 }
	 if ($cgi->param('mustTweetBroad') && $cgi->param('mustTweetBroad') eq "TweetEmAll") {
		 $mustTweetBroadcast ="yeahcool";
	 }else{
		 $mustTweetBroadcast ="nones";
	 }
	 
	 if ($cgi->param('consumerKey') && length($cgi->param('consumerKey')) > 10 ) {
		 $consumer_key = $cgi->param('consumerKey');
	 }else{
		 $consumer_key = $consumer_key_default;
	 }
	 if ($cgi->param('consumerSecret') && length($cgi->param('consumerSecret')) > 10 ) {
		 $consumer_secret = $cgi->param('consumerSecret');
	 }else{
		 $consumer_secret = $consumer_secret_default;
	 }
	 if ($cgi->param('axxToken') && length($cgi->param('axxToken')) > 10 ) {
		 $access_token = $cgi->param('axxToken');
	 }else{
		 $access_token = $access_token_default ;
	 }
	 if ($cgi->param('axxTokenSecret') && length($cgi->param('axxTokenSecret')) > 10 ) {
		 $access_token_secret = $cgi->param('axxTokenSecret');
	 }else{
		 $access_token_secret = $access_token_secret_default ;
	 }
	 
	 #################################
	 #penis 
	 
	 ########## custom rss feeds ################
	 
	 	if ($cgi->param('mustCommunityBroad') && $cgi->param('mustCommunityBroad') eq "gimmeUpdates") {
		 $mustCommunityBroadcast = "yeahcool";
		 
		 
		 if ($cgi->param('feedlist') && length($cgi->param('feedlist')) > 20) {
			 @communityfeeds = split("\n",$cgi->param('feedlist'));
			 
		 }else{
			 undef @communityfeeds;
		 }
		 
	 }else{
		 $mustCommunityBroadcast = "nones";
	 }
	 
	 ##########################################
	 
	 ############ transmission options #############
	 
	 		 if ($cgi->param('encryption') && $cgi->param('encryption') eq "encrypt") {
			 if ($mustEncrypt eq "nones") {
			 $mustEncrypt = "yeahbabygetthisoneintoyourassFCCandNSA";
			 $modifiedoptions = "yeah";
		 }
			 if ($cgi->param('passphrase') ne $passphrase) {
				
			      $passphrase = $cgi->param('passphrase');
			      $modifiedoptions = "yeah";
			      
		      }
			 }else{
				 if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
				 $mustEncrypt = "nones";
				 $modifiedoptions = "yeah";
			 }
				 }
		 
		 if ($cgi->param('modes') ne $currentmodem) {
			 $currentmodem = $cgi->param('modes');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
		 
		 if ($cgi->param('freqcursor') ne $frequencycarrier) {
			 $frequencycarrier = $cgi->param('freqcursor');
			 $changemodemsettings = "yeah";
			 }else{
				 
				 } 
			 
		if ($cgi->param('answer2resend') && $cgi->param('answer2resend') eq "answresend" ) {
			
			if ($mustAnswerResendreq eq "nones" ) {
			$mustAnswerResendreq = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ($mustAnswerResendreq eq "yeahbaby" ) {
			$mustAnswerResendreq = "nones";
			$modifiedoptions = "yeah";
		   }

		}
		if ($cgi->param('askresend') && $cgi->param('askresend') eq "askresend" ) {
			if ( $mustAsk2resend eq "nones" ) {
			$mustAsk2resend = "yeahbaby";
			$modifiedoptions = "yeah";
		   }
		}else{
			if ( $mustAsk2resend eq "yeahbaby" ) {
			$mustAsk2resend = "nones";
			$modifiedoptions = "yeah";
		   }
		}

        
        #### callsign ########
        
        	 if ($cgi->param('useCallsign') && $cgi->param('useCallsign') eq "usethisCallsign") {
			    if ($mustUseCallSign eq "nones") {
			       $mustUseCallSign = "yeah";
			       $modifiedoptions = "yeah";
		         }
			    if ($cgi->param('callsign') && length($cgi->param('callsign')) >= 2 ) {
				
			        $callsign = $cgi->param('callsign');
			        $modifiedoptions = "yeah";
			      
		          }else{
					 undef $callsign;
					 $mustUseCallSign = "nones";
				 } 
			 }else{
				 if ($mustUseCallSign eq "yeah") {
				   $mustUseCallSign = "nones";
				   $modifiedoptions = "yeah";
				   #undef $callsign;
			     }
			}
        
        
        ################
        

		if ($changemodemsettings && $changemodemsettings eq "yeah") {
			main::modem_setting($currentmodem, $frequencycarrier);
			undef $changemodemsettings;
		}
	 
	 #######################################################
	 
	 
	 main::save_settings();
 }
    my  $etorproxyhost = HTML::Entities::encode_entities($torproxyhost); 
    my  $etorproxyport = HTML::Entities::encode_entities($torproxyport);
    my  $eproxyhost = HTML::Entities::encode_entities($proxyhost);
    my  $eproxyport = HTML::Entities::encode_entities($proxyport);
    my  $eproxyuser = HTML::Entities::encode_entities($proxyuser) if defined $proxyuser;
    my  $eproxypass = HTML::Entities::encode_entities($proxypass) if defined $proxypass;
    
    my  $epassphrase = HTML::Entities::encode_entities_numeric($passphrase, '<>&"') if defined $passphrase; 
    my  $ecallsign = HTML::Entities::encode_entities($callsign) if defined $callsign;
    
    my  $efrequencycarrier = HTML::Entities::encode_entities($frequencycarrier);
    
    my  $econsumer_key = HTML::Entities::encode_entities($consumer_key);
    my  $econsumer_secret = HTML::Entities::encode_entities($consumer_secret);
    my  $eaccess_token = HTML::Entities::encode_entities($access_token);
    my  $eaccess_token_secret = HTML::Entities::encode_entities($access_token_secret);
     
     print qq{$headerz};
     print qq {<p style="text-align:right;font-size:18px;"><a href="/" ><img src="data:image/png;base64,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" title="Back to Message" border="0" width="60" height="60"></a></p></br>};
	
	 print qq{$ergumlogos};
    
     print qq{<h2> Internet Gateway Services</h2><form name="formGateway" method="POST" >};
    
     print qq{<input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Save Preferences" ></br></br>};

     print qq{<h3> ZonkeyNet Server Access </h3></br>};
   
    if ($mustListenAllInterfaces eq "yeah") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustListenAll" value="yeahyeah" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustListenAll" value="yeahyeah" />};
			}	
			print qq{Do You Want to make ZonkeyNet available for all users on your network? </br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;By default ZonkeyNet listens for all incoming connections , 
			</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if you want to make it available only for localhost uncheck this,</br>
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;advanced settings like these ones are available only from localhost.};
	  print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<code>(Refresh This Page after Changing This Setting.)</code></br></br>};
     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>Contacts:</b>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="/addKey" ><code>add a new key</code></a>};
     print qq {&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="/delKey" ><code>delete an existent key</code></a>};

    #no, we didnt forget weev.. <3
    print qq{<h3> News </h3></br>};
    
    if ($mustNewsBroadcast eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustNewsBroad" value="gimmeNews" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustNewsBroad" value="gimmeNews" />};
			}	
			print qq{Do You Want to broadcast News to other users, over the air, from your internet access? </br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Really simple. Keep other people, without access to internet, informed about what is going on.</br></br>};

   print qq{<h3> Community News and Personalized Feeds </h3></br>};
    
    if ($mustCommunityBroadcast eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustCommunityBroad" value="gimmeUpdates" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustCommunityBroad" value="gimmeUpdates" />};
			}	
			print qq{Do You Want to broadcast updates related to your Community to other users, over the air, from your internet access? </br>
		&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Keep other people, without access to internet, updated about your community.</br></br>};
       
       
       print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Paste here URLs of those RSS you want to broadcast (one address per line):</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};

	   if (@communityfeeds) {
		   my $listfeeds = join("\n",@communityfeeds);
		   $listfeeds = HTML::Entities::encode_entities($listfeeds);
       		   print qq{<textarea name="feedlist" rows="6" cols="100"  placeholder="http://megacool.org/lastnyancatfeed.xml" maxlength=500 >$listfeeds</textarea>};

       }else{
		       print qq{<textarea name="feedlist" rows="6" cols="100" placeholder="http://megacool.org/lastnyancatfeed.xml" maxlength=500 ></textarea>};
   
	   }
	  print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<code>(Verify your links are correct and available or they will be ignored otherwise.)</code>};


     print qq{</br></br><h3> Twitter </h3></br>};
     
      if ($mustTweetOthers eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweet" value="beCoolAndTweet" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweet" value="beCoolAndTweet" />};
			}
			print qq{Do You Want to offer other users to send tweets via your internet access?</br></br>};
			
		      if ($mustTweetBroadcast eq "yeahcool") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweetBroad" value="TweetEmAll" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="mustTweetBroad" value="TweetEmAll" />};
			}	
			print qq{Do You Want to broadcast twitter streams, over the air, from your internet access? </br></br>};
			
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<code>(Look below for instructions how to setup and general help about this.)</code>};

     print qq{</br></br></br><p>Twitter OAuth required credentials:</p>};

     print qq{<table>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Consumer Key:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input name="consumerKey" maxlength=90 placeholder="$econsumer_key" value="" size="90"></div></td></tr>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Consumer Secret:&nbsp;&nbsp;&nbsp;&nbsp;<input name="consumerSecret" maxlength=90 placeholder="$econsumer_secret" value="" size="90"></div></td></tr>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Access Token:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input name="axxToken" maxlength=90 placeholder="$eaccess_token" value="" size="90"></div></td></tr>};
     print qq{<tr><td><div id='smallf'> &nbsp;&nbsp;&nbsp;&nbsp;Access Token Secret:&nbsp;&nbsp;&nbsp;&nbsp;<input name="axxTokenSecret" maxlength=90 placeholder="$eaccess_token_secret" value="" size="90"></div></td></tr>};




     print qq{</table></br></br><p>How do I get this done?</p>};

     print qq{<p>OK go to Twitter and sign in for the new account you want to dedicate to this stuff.</br> Once you get all done, go to the Twitter Developer page and login using this new account credentials.</br> then create a New Application, get the consumer key and consumer secret values and put them here,</br> then request new tokens with writting rights and fill token access key and token access secret fields here.</br>then save and enjoy your mojito</p>};

     print qq{<p>hmmm...well..if you are still feeling lost then check the following tutos about how to do it:</br>

<a href="http://www.themepacific.com/how-to-generate-api-key-consumer-token-access-key-for-twitter-oauth/994/">How to Generate API Key, Consumer Token, Access Key for Twitter OAuth</a></br>
<a href="http://www.themebeans.com/how-to-create-access-tokens-for-twitter-api-1-1/">How to Create your Access Tokens for Twitter</a></br>
</br></br></br>
};

       print qq{<h3> Tor and Proxy </h3></br>};
       
          if ($mustUseProxy eq "nones") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="direct" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="direct" />};
			}	
			print qq{Direct Access to Access Internet.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</br></br></br></br></br>};

    
    if ($mustUseProxy eq "useTor") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useTor" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useTor" />};
			}	
			print qq{Use Tor to Access Internet.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};
     print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Tor Service Listening at : &nbsp;&nbsp;<input name="torproxyhost" maxlength=24 value="$etorproxyhost" placeholder="Tor Service IP Address" size="12">&nbsp;&nbsp;&nbsp;&nbsp;Port:&nbsp;&nbsp;<input name="torproxyport" maxlength=5 value="$etorproxyport" placeholder="Port" size="5"></br></br></br></br>};
    
      if ($mustUseProxy eq "useProxy") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useProxy" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="radio" name="mustUseProxy" value="useProxy" />};
			}	
			print qq{Use a Proxy to Access Internet.&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};
		
     print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Proxy IPv4 Address: &nbsp;&nbsp;http://<input name="proxyhost" maxlength=24 value="$eproxyhost" placeholder="Proxy address" size="12">&nbsp;&nbsp;&nbsp;&nbsp;Port:&nbsp;&nbsp;<input name="proxyport" maxlength=5 value="$eproxyport" placeholder="Port" size="5">};

     if ($eproxyuser && length($eproxyuser) > 2) {
      print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;User: <input name="proxyuser" maxlength=24 value="$eproxyuser" placeholder="User" size="10">};
       }else{
	   print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;User: <input name="proxyuser" maxlength=24 value="" placeholder="User" size="10">};
      }

     if ($eproxypass && length($eproxypass) > 2) {
       print qq{&nbsp;&nbsp;&nbsp;&nbsp; Password: <input name="proxypass" maxlength=64 value="$eproxypass" placeholder="Password" size="10">};
     }else{
	   print qq{&nbsp;&nbsp;&nbsp;&nbsp; Password: <input name="proxypass" maxlength=64 value="" placeholder="Password" size="10">};
      }

     print qq{</br></br></br></br></br><table>};

     print qq{<h3> Data Transmission Options</h3></br> <tr><td>};

   if ($mustEncrypt eq "yeahbabygetthisoneintoyourassFCCandNSA") {
		print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" checked />};
		}else{
			print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type="checkbox" name="encryption" value="encrypt" >};
			}
			print qq{ Encrypt/Decrypt Messages with Passphrase: <input name="passphrase" maxlength=140 placeholder="Passphrase" value="$epassphrase" size=36>&nbsp;&nbsp;&nbsp; (AES-256)</td></tr>
   </tr></td><tr><td></br></br><div id='smallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Data Transmission Mode: <select name="modes">
  <option value="$currentmodem" selected>$currentmodem</option>
  <option disabled>---</option>
  <option value="BPSK31">BPSK31</option>
  <option value="QPSK31">QPSK31</option>
  <option value="QPSK250">QPSK250</option>
  <option value="QPSK500">QPSK500</option>
  <option value="PSK500R">PSK500R</option>  
  <option value="PSK1000R">PSK1000R</option>
  <option value="MFSK64">MFSK64-Image</option>
  <option value="MFSK128">MFSK128-Image</option>

  <option value="PSK63RC5">PSK63RC5</option>
<option value="PSK63RC10">PSK63RC10</option>
<option value="PSK63RC20">PSK63RC20</option>
<option value="PSK63RC32">PSK63RC32</option>
<option value="PSK125RC12">PSK125RC12</option>
<option value="PSK125RC16">PSK125RC16</option>
</select> &nbsp;&nbsp;&nbsp;&nbsp;Carrier Frequency center:<input name="freqcursor" maxlength=4 value="$efrequencycarrier" size="4"></div></td></tr>
<tr><td><div id='xsmallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(Do Not Change This, if you are not sure about what are you doing.)</div></td>
<tr><td></br></br><div id='smallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Automatically: &nbsp;&nbsp;};

    if ( $mustAsk2resend eq "yeahbaby") {
	 print qq{<input type="checkbox" name="askresend" value="askresend" checked>};
	  }else{
		 print qq{<input type="checkbox" name="askresend" value="askresend" >};
		}
	print qq{Ask others to resend messages when I received them corrupted&nbsp;&nbsp;&nbsp;&nbsp;  };
	
    if ( $mustAnswerResendreq eq "yeahbaby" ) {
	 print qq{<input type="checkbox" name="answer2resend" value="answresend" checked>};
	   }else {
		print qq{<input type="checkbox" name="answer2resend" value="answresend" >};
		 }
		
	 print qq{Answer requests from others to resend messages</div></td></tr>
	<tr><td><div id='xsmallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(resending back and forth can be annoying, use it only when needed)</div></td></tr>};


     print qq{<tr><td></br></br><div id='smallf'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;};
      if ($mustUseCallSign eq "yeah") {
		print qq{<input type="checkbox" name="useCallsign" value="usethisCallsign" checked>};
		}else{
			print qq{<input type="checkbox" name="useCallsign" value="usethisCallsign" >};
			}
			
			 if ($ecallsign) {
			print qq{ Include this Call Sign in your messages: <input name="callsign" maxlength=36 placeholder="Call Sign" value="$ecallsign" size=36>};
		 }else{
			 			print qq{ Include this Call Sign in your messages: <input name="callsign" maxlength=36 placeholder="Call Sign" value="" size=36>};
			 			

		 }
     print qq{&nbsp;&nbsp;(Optional)&nbsp;&nbsp;&nbsp;</div></td></tr>};

     print qq{</table></br></br></br></br></br>};

     print qq{<input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Save Preferences" ></form></br></br></br></br>};

     print qq{$footerz};
     
	}
 }  
 
sub show_tables {
	
	
	 print qq {Content-type: text/plain\n\n};
     print qq{######################################################\n};
     print qq{###                   TABLES                       ###\n};
     print qq{######################################################};
     print qq{\n\n================================================================\n\n};
	
	
	print qq{CAN LISTEN TO: \n};
	
	foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canListen'} ) {
		  
		    print qq{$contacted \n};
            
	   }
		  
	  }
	print qq{---------------------------------------\n\n};
	
	print qq{CAN TALK TO: \n};
	
		foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canTalk'} ) {
		  
		    print qq{$contacted \n};
            
	   }
		  
	  }
	
	print qq{---------------------------------------\n\n};
	
	print qq{CAN EXTENSIVELY TALK TO: \n};
	
		foreach my $contacted ( keys %rtable) {
		  
		  if ( $rtable{$contacted}{'canTalkExtended'} ) {
		  
		    print qq{$contacted via $rtable{$contacted}{'via'}\n};
            
	   }
		  
	  }
	
} 
 
 
sub add_buddy_key {

	 my $cgi  = shift;   
     return if !ref $cgi;
     
     my $usedIp = $cgi->remote_host(); 
     
     my $addedkey;
     
     
     my $keyexample = qq{<code><pre>
How do this? 

Get the RSA public key from the radio node or the contact you want to
send encrypted messages to. 
Valid public keys are automatically generated for each ZonkeyNet node,
and that public key should be available at :

'http://someuser.zonkeynet.ip.address:port/publicKey.pem'

*Airchat automatically produces RSA keys of 2048 bits for its users
The RSA public key should look like this (well..something similar):

-----BEGIN RSA PUBLIC KEY-----
xxxxblah..blah..xxxxxx.blah..err...etc...random.characters...xxx
jKBf71aWKmUtkU96S4Gvi7M/oGX5dp5GCpY77eAWVxFB1OXvyVN40EhAowrDNtnL
.....xxxxxxxxxxx....blah..blah....................more.random..X
J5iKpZWksyP0W7V/KyPOuyINUO+9gKcMZ1DYCBdmuXT7oAEnobUH5Z3TweyWoygw
xxxxblah..Keith Alexander loves cocksxx..his hair is weird...xxx
xxxxblah..err...etc..also..c0cks...xxx
-----END RSA PUBLIC KEY-----


then write the name or something that can help you identify
the recipient whom public key belongs to,
then copy/paste the key on that box above and click on 'Save Public Key'
then enjoy.\n</pre></code>};
    
     if ($cgi->param('doitdoit') && $cgi->param('doitdoit') eq "Save Public Key" ) {
	
	  
	  if ($cgi->param('contact') && length($cgi->param('contact')) >=1 && $cgi->param('publicKey') && length($cgi->param('publicKey')) >=100) {
	  
	     my $keytowrite = $cgi->param('publicKey') ;
	      
	      if ( ($keytowrite =~ m/-----BEGIN RSA PUBLIC KEY-----/) && ($keytowrite =~ m/-----END RSA PUBLIC KEY-----/) ) {
	  
          my @cleaning = split("-----BEGIN RSA PUBLIC KEY-----",$keytowrite);
          my @cleaning2 = split("-----END RSA PUBLIC KEY-----",$cleaning[1]);
          $keytowrite = $cleaning2[0];
          $keytowrite = "-----BEGIN RSA PUBLIC KEY-----" . $keytowrite . "-----END RSA PUBLIC KEY-----\n";
          $keytowrite =~ s/\r//g;
          
	      
	      my $kcode = main::sha512_hex($keytowrite,"");
	       $kcode = substr($kcode,0,6);	
	      
	      if ( $dahfuckingkeys{$kcode} && $dahfuckingkeys{$kcode}{'Local'} ) {
			  
		  }else{
	      
	      $dahfuckingkeys{$kcode}{'pubK'} = $keytowrite;
	      $dahfuckingkeys{$kcode}{'name'} = $cgi->param('contact');
	      
	      main::save_keys();
	      $addedkey = "<div class='greentxt'><h2> The new Public Key was Succesfully added  </h2></div></br>";
	       }
	       }
	  
 
	    }
   }

       print qq{$headerz};
       print qq {<p style="text-align:right;font-size:18px;"><a href="/" ><img src="data:image/png;base64,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" title="Back to Message" border="0" width="60" height="60"></a></p></br>};
	
	   print qq{$ergumlogos};
    
       print qq{<h2> Add a new RSA Public Key for your Contacts</h2></br><form name="formAddKey" method="POST" >};
     

       print qq{$addedkey} if $addedkey;
       print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Name/Nick/Callsign/other : &nbsp;&nbsp;<input name="contact" maxlength=140 placeholder="something" value="" size=36>&nbsp;&nbsp;&nbsp; };
	   print qq{</br></br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <textarea name="publicKey" rows="15" cols="90"  placeholder="Paste the RSA Public Key here." maxlength=2000 ></textarea>};

       print qq{</br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Save Public Key" ></form></br></br></br>};
	    
	   print qq{$keyexample};
	    
	    
	   print qq{$footerz};
    
   
}

sub del_buddy_key {
     my $cgi  = shift;   
     return if !ref $cgi;
     my $usedIp = $cgi->remote_host(); 
     
     if ($usedIp eq "127.0.0.1") {
		 
	 my $deletedkey;

     if ($cgi->param('doitdoit') && $cgi->param('doitdoit') eq "Delete Public Key" ) {
		 
	  if ($cgi->param('pubkeys') && length($cgi->param('pubkeys')) >=1 ) {
	     my $keytodel = $cgi->param('pubkeys') ;
	      
          delete $dahfuckingkeys{$keytodel};
          main::save_keys();
         $deletedkey = "<div class='greentxt'><h2> The chosen Public Key was Succesfully deleted  </h2></div></br>";

	  
       }
	}


     print qq{$headerz};

     print qq {<p style="text-align:right;font-size:18px;"><a href="/" ><img src="data:image/png;base64,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" title="Back to Settings" border="0" width="60" height="60"></a></p></br>};
	
     print qq{$ergumlogos};
    
     print qq{<h2> Delete a Public Key </h2></br><form name="formDelKey" method="POST" >};
     
     print qq{$deletedkey} if $deletedkey;
     
     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Choose a Public Key to delete by its linked Name/Nick/Callsign/other : <select name="pubkeys" placeholder="Choose...">};
      foreach my $publickey ( keys %dahfuckingkeys) {
		  
		  if ( !$dahfuckingkeys{$publickey}{'Local'} ) {
		  
		  my $name = HTML::Entities::encode_entities_numeric($dahfuckingkeys{$publickey}{'name'}, '<>&"');
		  my $kcode = HTML::Entities::encode_entities_numeric($publickey, '<>&"');
		  
		  print qq{<option size="15" value="$kcode" >$name</option>};
	   }
		  
	  }
     print qq{</select></br></br>};

     print qq{&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <input type="submit" name="doitdoit" style="height: 45px; width: 170px" value="Delete Public Key" ></form></br></br></br></br>};
	 print qq{$footerz};
	
   }
}


sub get_my_publickey {
	print "Content-type: text/plain\n\n";
	foreach my $publickey (sort { $dahfuckingkeys{$a} cmp $dahfuckingkeys{$b} } keys %dahfuckingkeys) {
	if ( $dahfuckingkeys{$publickey}{'Local'} ) {
	
	print $dahfuckingkeys{$publickey}{'pubK'};
    }
     }
}


sub about_and_shits {
	
	my $diagram1 = '<img width="900" src="data:image/png;base64,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" alt="diagram1" />';
	my $diagram2 = '<img width="900" src="data:image/png;base64,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" alt="diagram2" />';		
	my $usercases = qq{	
<h2>User cases</h2><p class="content" >
People who were protesting against their govt resulting in the their internet being cut off. 
Even worse govt decided to fuck with their cellphones networks too. 
They need basic communication tools to spread news and updates about their conditions, 
and with the aim to eventually relay that information to/from the internet 
when at least one of them is able to get a working internet connection.

NGOs and medical teams working in Africa under poor conditions who want to build some
basic communication's infrastructure to coordinate efforts like the delivery of 
medication and food or to update on local conditions 
without being intercepted by regional armed groups etc.

Dissident groups who mistrust the normal communication infrastructure and who want to coordinate
regional activity and share updates about oppressive actions carried out by the authorities.

Disaster response, rescue and medical teams who are working in devastated zones without the availability 
of standard telecommunication infrastructure. They want to keep updating their statuses, 
progress and resource availability between teams when there may be large overage zones between them.

Yacht owners who are sailing and who wish to obtain news updates from some approaching coastline
or another ship which has internet access. There may just be a simple exchange of information 
about news, weather conditions, provisions, gear etc.

Local populations who want to keep in touch with each other on a daily basis with the goal of developing 
a strong community capable of maximizing their resources, 
food or manpower to help improve sustainability and their quality of life.

Street protests or any other street event where people would like to share their thoughts, 
anonymously and locally without relying on the internet. They may also wish to share them 
with the world as a single voice using a simple gateway such as a unique Twitter account made for the occasion.

Expedition basecamps who need a simplistic solution to build a common gateway for establishing 
radio communication and messaging service links with camps, remotely located basecamps and/or 
rescue teams to coordinate tasks such as logistics, rescue efforts, routes and schedules.
</p>};

my $dilemmas = qq{
<h2>Background: Dilemmas and decisions</h2>
Every project is a fractalized representation of infinite dilemmas sparkling other new ones,
glued to the futile decisions we make, to try to address all of them.

Many ideas have crossed our minds when we tried to make this thingie.
We experimented broadcasting UDP packets inside mesh network solutions.
We experimented using patched wireless network card drivers to inject crafted wifi management frames.
We also considered crafting TDMA packets via cellphones RF hardware.
We thought about those many different possibilities. we saw there's so much potential on them. 
Sadly we found out how locked down and overregulated our communication devices are.

So, we thought: 'Well some solutions would require that we ask people to root their phones or routers, and 
to then install custom firmwares with patched drivers, with the risk of getting people mad cause they
were bricking them'

we also thought about a Wifi interconnected cellphone net approach, but the coverage range was frustrating.

We saw people working on different mesh related projects and we thought 
'One solution shouldn't discard another one but it should try to complement it, 
to add interoperability and to allow heterogeneous systems'. 
As different serious projects are looking for solutions based on 802.11 standards we said, 
'WTF lets try to reinvent the wheel for exploration and fun'.

But to reinventing the wheel you need freedom. a freedom which we don't have much of in on our world 
of telecommunications, which is over-regulated by evil organizations like the FCC and similars shits around the world. 
So we choose the good ol' trusted ancient technology to start free.

Radio transceivers.
yeah, these shits rock.
we chose to sacrifice bandwidth for freedom.
Tune the frequency.
Define a protocol.
Transmit.
Enjoy.

};

my $quickstart = qq{

<h2>Quick Start</h2><h3>Software Setup</h3>
<b>FreeBSD 10</b>
from a fresh server install:
<code>
# pkg install make
# pkg install perl-5.16.xx
# perl install-modules-zonkeynet-freebsd.pl
</code>
then...
<code>
# cpanp
CPAN Terminal> i Net::Server --skiptest
CPAN Terminal> i HTTP::Server::Simple::CGI::PreFork
</code>
that will get you the zonkeynet server running,
keep in mind installing fldigi requires a graphical environment aka X
so,
1: you setup zonkeynet to connect with a remote station running fldigi
2: install X and then:
<code>
# pkg install fldigi-3.xx.xx
</code>


<b>Windows</b>
Install Strawberry Perl >= 5.18 (the portable zip version fits well for example)
from http://strawberryperl.com/

Direct link:
http://strawberryperl.com/download/

Once you get perl installed, run in your perl shell:
<code>
# perl install-modules-zonkeynet-windows.pl
</code>
Then install these modules via the cpanplus terminal:
<code>
# cpanp
CPAN Terminal> i Net::Server --skiptest
CPAN Terminal> i HTTP::Server::Simple::CGI::PreFork --skiptest
</code>
Then install fldigi from:
http://www.w1hkj.com/download.html


<b>Linux (Debian / tested also on Ubuntu Trusty)</b>
Install some needed stuff:
<code>
# apt-get install make libcpanplus-perl libhttp-server-simple-perl libcrypt-cbc-perl libcrypt-rijndael-perl librpc-xml-perl libxml-feedpp-perl liblwp-protocol-socks-perl libnet-twitter-lite-perl libnet-server-perl
</code>
(There's an optional and commented "use Net::SSLGlue::LWP" before "use LWP::UserAgent" on zonkey.pl (# apt-get install libnet-sslglue-perl),
This magically fixes LWP for https requests issues, when for example you want to include feeds only available via proxy to a https address,
if you don't have the updated libwww-perl 6.05-2 and liblwp-protocol-https-perl 6.04-2 available from repositories 
(should be available from the jessie repos thou)) but...
We strongly recommend you look to update libwww-perl and liblwp-protocol-https-perl to their latest versions, 
cause using SSLGlue will eventually break https access to the twitter API.

Check if you have updated packages for 'libnet-twitter-lite-perl' because you will need the Twitter API v1.1 support.
run:
<code>
# perl install-zonkeynet-modules-linux.pl
</code>
^ this will install 'HTTP::Server::Simple::CGI::PreFork' (needed) and 'Net::Twitter::Lite::WithAPIv1_1'

If you want to install Fldigi on the same machine than ZonkeyNet then:
<code>
# apt-get install fldigi
</code>
(running fldigi requires a graphical environment)


<b>MacOS X</b>
Get XCode.
Launch XCode and bring up the Preferences panel. Click on the Downloads tab. Click to install the Command Line Tools. Check you got 'make' installed.
run:
<code>
# perl install-zonkeynet-modules-macosx.pl
# cpanp
CPAN Terminal> i Net::Server --skiptest
CPAN Terminal> i HTTP::Server::Simple::CGI::PreFork --skiptest
</code>

<b>General Notes</b>
ZonkeyNet runs by default on port 8080, connect your browser to (for Example: http://localhost:8080). READ THE CODE.
If you find some problem running zonkeynet, 
please try updating modules and linked libraries.
we've found some issues related to outdated implementations.
(like '500 Bad arg length for Socket6::unpack_sockaddr_in6, length is 16, should be 28'
happening in Ubuntu Precise when enabling the Twitter gateway)

<b>Fldigi Setup</b>
run fldigi.
skip everything if you want but
you must configure audio devices to make it work with your capture device
and your audio output device. test if it's working capturing audio signals and playing audio.
and that's all.

(Note: keep your fldigi updated always)
};

my $hardwaresetup = qq{
<h3>Hardware Setup</h3>
Radio transceivers usually come with many different interfaces,
Each brand deploys different connectors even within their own range of models and
sadly there's usually no standard which they follow.

We understand that some people have experience using more expensive
radio equipments and will know how to link those transceivers to their computers.
As such we will focus on supporting the cheapest and most accesible models which are able
to offer the democratization of this solution worldwide even in the poorest regions.

We have considered cheap chinese vhf/uhf fm handheld transceivers
available worldwide at as low as \$40 bucks each.

These devices come with a Kenwood 2-pin connector composed by a 2.5mm jack and a 3.5mm one.
The 2.5mm jack transports the speaker signal and the 3.5mm serves as the microphone input.

We will make a very simple setup using the VOX function on the transceiver to avoid more complex PTT setups.

First connect some 2.5mm male to 3.5mm male cable between the speaker output on the radio and the
microphone input on your computer. 

Then take a stereo 3.5mm male to 3.5mm male cable and cut all of the small
cables inside except the red one (It should be a red cable which is connected to the middle ring of the jack).
<u><b>Only the red cable with the signal coming from the ring of the 3.5mm jack should be connected and nothing else.
(neither the tip, nor the ground (ground will be provided by the 2.5mm jack cable)).</b></u>

Once you are done, connect this customised cable to the microphone input on the
radio transceiver and then to the speaker output of your computer.

Finally, set the frequency everyone will use on the transceiver,
Don't forget to enable the VOX function (adjust the sensitivity to medium).
Modify the transmission timer to more than 2 minutes, set the radio speaker volume to approx. 50%,
tune the microphone sensitivity on your computer to base levels with medium boost (if needed) and finaly
set the computer headphones volume to around 70% or so and then you are ready to go. keep testing till
getting the best audio quality for your transmission.

Be careful about the quality of cables and soldering used, test the audio quality until getting the 
most optimal conditions possible, that will directly improve your transmissions.


};


    $usercases =~ s/\n/\<\/br\>/g;
    $quickstart =~ s/\n/\<\/br\>/g;
    $hardwaresetup =~ s/\n/\<\/br\>/g;
    
		
	print qq{$headerz};

    print qq {<p style="text-align:right;font-size:18px;"><a href="/" ><img src="data:image/png;base64,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" title="Back to Message" border="0" width="60" height="60"></a></p></br>};
	
    print qq{$ergumlogos};
    
    ### intro ###
    print qq{$usercases};
    
    ### dilemmas ###
    
    ### diagrams ####
    print qq{<h2>Some Possible RF Network Configurations</h2></br>};
    print qq{</br></br>$diagram1 </br></br></br>$diagram2</br></br>};
    
    ### quick start ###
    
    print qq{$quickstart};
    
    print qq{$hardwaresetup};
    
    ### questions ###      
    
    print qq{$footerz};
	
}



 } 
 
 $SIG{ALRM} = sub {
	&refresh_last_msgs(); 

	alarm 30;};
        alarm 30;
 

 modem_setting($currentmodem, $frequencycarrier);

 my $cock;
        $cock = sprintf("%.12f",scalar(Time::HiRes::gettimeofday()));
        $cock = gmtime(Time::HiRes::gettimeofday());
        print "\nStarted at:  $cock \n";

 $pid = ZonkeyServer->new($ZonkeyPort);
if ($mustListenAllInterfaces eq "nones") {
 $pid->host('127.0.0.1');
}
# $pid->run();
 $pid->run(prefork => 1);

#
