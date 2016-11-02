# raw_udp_peer-to-peer,ncurses_chat_client_for_localhost

The most useless chat client you'll never need.<br>
A raw socketed, peer-to-peer, home-brew UDP building, ncurses based - "chat" client..<br>
<br>
It's a mess! You're a fool for using it!<br>
<br>

# But why?

As far as overengineering something goes, this is my prime project!<br>
I needed a chat application for me and a friend (who sits in the same room),<br>
I tried setting up a broadcast UDP socket, for whatever reason that didn't work<br>
due to UDP binding to a socket still assumes server/client roles.<br>
<br>
So I tried shared memory between processes, turns out writing to `/dev/mem` randomly<br>
wasn't such a great idea anywhere really. A few system-crash:es later.. I scrapped that..<br>
<br>
So what about a database you might ask? Meh.. Don't want something clunky ruining my Feng Shui!<br>
"But surely a server software to relay messages would be better?" - Sceptics... Pff.. Who needs those..<br>
<br>
So I did what any bored engineer with curiosity would do (who am I kidding),<br>
I based a interface on `ncurses`, then I created a raw socket without any automated headers,<br>
I then recieved, unpacked and displayed whatever comes in on localhost:5554.<br>
Finally I built the most ugly UDP builder ever to send out messages on the same interface and port<br>
making sure the checksum going out (Which will be detected in a second) is blocked from replaying in the interface.<br>
<br>
And there you have it, a peer-to-peer, raw UDP, chat client for localhost!<br>
<br>
I'm out of here!
