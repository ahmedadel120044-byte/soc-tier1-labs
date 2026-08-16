🔍 WireDive - Complete Walkthrough & Network Forensic Analysis

🌐 Part 1: Network & Protocol Analysis (Q1 - Q5)

Q1: What is the FTP password?
Answer: AfricaCTF2021
Forensic Source: تم العثور على كلمة السر بنص واضح (Cleartext) داخل باكيتات الـ FTP المتبادلة باستخدام الفلتر `ftp.request.command == "PASS"`.

Q2: What is the IPv6 address of the DNS server used by 192.168.1.26?
Answer: fe80::c80b:adff:feaa:1db7
Forensic Source: استخراج العنوان من طلبات الـ DNS الموجهة عبر بروتوكول IPv6 من الجهاز الفحص.

Q3: What domain is the user looking up in packet 15174?
Answer: www.7-zip.org
Forensic Source: تم الوصول للباكيت برقمها المباشر 15174 وفحص حقل الـ Query داخل بروتوكول DNS.

Q4: How many UDP packets were sent from 192.168.1.26 to 24.20.217.246?
Answer: 10
Forensic Source: تم استخدام الفلتر `ip.src == 192.168.1.26 && ip.dst == 24.20.217.246 && udp` وحساب عدد الباكيتات المفلترة.

Q5: What is the MAC address of the system under investigation in the PCAP file?
Answer: c8:09:a8:57:47:93
Forensic Source: تم استخراجه من الـ Ethernet Header الخاص بالجهاز صاحب الأي بي `192.168.1.26`.

🔐 Part 2: EXIF & Encrypted Traffic Forensics (Q6 - Q8)

Q6: What was the camera model name used to take picture 20210129_152157.jpg?
Answer: LM-Q725K
Forensic Source: تم إعادة تجميع واستخراج الصورة من الترافيك (Export Objects) وقراءة بيانات الـ EXIF Metadata الخاصة بموديل الكاميرا.

Q7: What is the ephemeral public key provided by the server during the TLS handshake in the session with the session ID: da6a000ea31e1b731518d73d0dtbeak71cc301ac1629810867efad16cc07f1ff?
Answer: 04edcc123ef7b13e90cef01a31c2f996f471a7c8f48a1b81d785085f5481
Forensic Source: البحث بـ Session ID داخل جلسات الـ TLS وقراءة قيمة الـ Pubkey من رسالة `Server Key Exchange` (أو `key_share` extension).

Q8: What is the first TLS 1.3 client random that was used to establish a connection with protonmail.com?
Answer: 24e92513b97a0348f733d18998929a79ba21b0b1400cd7a2882a732c
Forensic Source: تم الفلترة على الـ Client Hello الخاصة بالـ SNI لـ `protonmail.com` واستخراج قيمة الـ Client Random الأولى.

📁 Part 3: FTP Server & Web Artifacts (Q9 - Q11)

Q9: Which country is the manufacturer of the FTP server's MAC address registered in?
Answer: United States
Forensic Source: تم أخذ أول 3 خانات من الـ MAC Address الخاص بالـ FTP Server والبحث عن الـ OUI Manufacturer والذي يتبع شركة مسجلة في أمريكا.

Q10: What time was a non-standard folder created on the FTP server on the 20th of April?
Answer: 17:53
Forensic Source: تم رصد أمر إنشاء المجلد `MKD` في سجلات الـ FTP بتاريخ 20 أبريل واستخراج توقيت الباكيت.

Q11: What URL was visited by the user and connected to the IP address 104.21.89.171?
Answer: http://dfir.science/
Forensic Source: مطابقة الـ IP الخاص بالسيرفر مع الـ Host Header المكتوب في طلبات الـ HTTP الموجهة له.
