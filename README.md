This is Tlen.pl protocol plugin for Pidgin.

There used to be an official website at <http://nic.com.pl/~alek/pidgin-tlen/> but now it is here, on github.

What is supported:

 * IMs
 * Adding/removing users from roster (user list stored on server)
 * Setting/changing status
 * Typing notifications
 * New email notifications
 * Multiuser chat + conferencing
 * Public directory (setting info about yourselves, searching for buddies)
 * Whiteboard sessions (this is not a part of the original protocol, works
   between pidgin clients only)
 * avatars (just for buddies; user avatar is not supported yet)
 
Installation instructions for Windows users (TODO: test, fix, doesn't it work?)

 * copy libtlen.dll to c:\Program Files\Pidgin\plugins directory
 * for each tlen_XX.png file copy it to relevant directory:
		c:\Program Files\Pidgin\pixmaps\pidgin\protocols\XX\tlen.png
		

My kudos to
 
 * Krzysztof Godlewski <<sigsegv@tlen.pl>> -- chats, whiteboard, fixes
 * Adam Mazur <<ghr@o2.pl>> -- resurecting project after years of inactivity ;-)

Copyright 2005-2012 Aleksander Piotrowski <aleksander.piotrowski@nic.com.pl>
