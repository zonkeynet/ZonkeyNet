# ZonkeyNet
<pre>
<code>
   _  _   __________             __                               __   
__| || |__\____    /____   ____ |  | __ ____ ___.__. ____   _____/  |_ 
\   __   /  /     //  _ \ /    \|  |/ // __ <   |  |/    \_/ __ \   __\
 |  ||  |  /     /(  <_> )   |  \    <\  ___/\___  |   |  \  ___/|  |  
/_  ~~  _\/_______ \____/|___|  /__|_ \\___  > ____|___|  /\___  >__|  
  |_||_|          \/          \/     \/    \/\/         \/     \/      
</code>
</pre>
<b><h1>Communicate directly, without using Internet or cellular infrastructure.</h1></b>
<p>
<b><h2>Radiocommunications in Emergency</h2></b>
</p>
<p>
<b>ZonkeyNet</b> (based on <a href="https://github.com/lulzlabs/AirChat/blob/master/airchat.pl" target="_blank" title="AirChat Code GitHub"><b>Airchat</b></a> coded by <b>LulzSec</b>) is a <b>Free Speech</b> digital communications protocol that doesn’t deal with expensive,highly-surveilled commercial and government controlled infrastructure.
<b>Create a mesh network</b>" between other ZonkeyNet users running the same software.</b>
Each node in this mesh network is defined by it’s ability to decrypt messages.
There’s no hardware ID, and no plain text transmitter identification.
</p>
<p>             
The Radio project uses <a href="http://sourceforge.net/projects/fldigi/files/" target="_blank" title="Fldigi Files"><b>Fldigi software</b></a> to communicate data it’s the software commonly used to broadcast <b>amateur radio stations</b> from a computer.
The current release right now focuses on messaging and it can be used as a simplistic message board inside a <b>LAN</b> and to rely communications between <b>radio nodes</b>. It has built-in internet gateway capabilities to offer users access to some basics such as <b>chat on IRC</b>, <b>tweeting</b>, retrieving <b>twitter streams</b>, <b>downloading news</b>, <b>community related articles</b>, etc.
</p>
<p>
The configuration system is <b>fully documented in <a href="https://github.com/lulzlabs/AirChat/blob/master/README.md" target="_blank" title="ZonkeyNet Infos">ZonkeyNet</a></b>.
Refer to this for the full documentation.
</p>
<p>
<hr>
</hr>
<b>Some useful commands in ZonkeyNet:</b>
</p>
<p>
:local (Send local Messages) 
</p>
<p>
:twitter (Streaming tweet from ZonkeyNet)
</p>
<p>
:tweet (Send Tweet with ZonkeyNet) 
</p>
<p>
:searchtwitter= (Search term or hashtag on Twitter)
</p>
<p>
:sup? (Streaming Feeds (list links)
</p>
<p>
:news? (Streaming News (list links)
</p>
<p>
!google (Search on google) 
</p>
<p>
!weather (Info Meteo) 
</p>
<p>
!wolf (Wolfram Alpha engine) 
</p>
<p>
!twitter (Search term or hashtag on Twitter) 
</p>
<p>
!youtube (Search video or artists on Youtube) 
</p>
<p>
!wiki (Search on Wikipedia) 
</p>
<p>
!np (LastFM plugin) 
</p>
and much more!!!
</p>
<p>
<b>#Notes</b> ZonkeyNet runs by default on port <b>8080</b>, connect your browser to <b>http://localhost:8080</b></a>
(Internet access can be <b>anonymized</b> via <a href="https://www.torproject.org/" <b="">Tor</a> and the built in proxy support).
</p>
<hr>
</hr>
<p>
<b><h3>SELF HOSTED SERVICES</h3></b>
</p>
<p>
ZonkeyNet Mesh Radio Network WebServer, <a href="http://wiki.mumble.info/wiki/Main_Page" target="_blank" title="Mumble wiki">Mumble Voip Server</a> + <a href="http://sourceforge.net/p/phpmumbleadmin/wiki/" target="_blank" title="PHPMumbleAdmin Wiki">PHPMumbleAdmin</a> + <a href="https://bitbucket.org/Flandoo/mumblecop" target="_blank" title="MumbleCop">BOT written in Ruby</a> for streaming music from youtube, soundcloud, and also radio online. Another <a href="https://github.com/SFTtech/sftmumblebotBOT" target="_blank" title="sftmumblebot Mumble/IRC"> BOT</a> to deliver messages from chat on the Mumble server to IRC and vice versa.
ZonkeyTube HTML GUI based on <a href="https://github.com/Rudloff/alltube" target="_blank" title="Alltube on GitHub">Alltube</a> code in order to extract a video URL from a webpage.
ZonkeyPad based on <a href="https://github.com/ether/etherpad-lite" target="_blank" title="EtherPad-lite on GitHub">EtherPad</a> + plugin (Draw, pad preview image and more, Tor + <a href="https://onionshare.org/" target="_blank" title="OnionShare">OnionShare</a> support, <a href="https://www.unrealircd.org/" target="_blank" title="UnrealIRCd">UnrealIRCd</a> Server + <a href="https://github.com/Grinnz/maverick" target="_blank" title="GitHub Mojo::IRC Bot framework">BOT for IRC commands</a>, searching on google, twitter, and much more.
</p>
<p>
</p>
<p>
<b><h2>Installation :</h2></b>
</p>
<p>
<b>RASPBERRY PI 3 Full Image iso link</b>: SOON! 
</p>
<p>
<b>.AirChatsettings</b> is the main configuration file. It puts the pieces together by including all remaining configuration files when starting up the web server.
The binary is called <b>zonkey.pl</b>. ZonkeyNet and Fldigi can be started/stopped with commands "<tt><b>zonkeynet (start:stop:restart)</b></tt>" typed in a terminal shell.
 You can also run the script by double clicking on its Desktop icon.
</p>
<p>
And of course the <b>NEW BOTS</b> to create a bridge between the <b>Airchat/ZonkeyNet radio</b> users and your preferred <b>IRC</b> Channel
</p>
