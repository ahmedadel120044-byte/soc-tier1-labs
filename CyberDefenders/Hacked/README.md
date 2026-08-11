اللاب ده فعلاً دسم وشامل تقريباً لجميع محاور الـ Linux Disk Forensics (من تحليل سجلات النظام Logs وإدارة المستخدمين Artifacts لحد استرجاع الملفات الممسوحة وتحليل الـ Web Root).

ده الشرح الكامل لجميع الأسئلة الـ 19 والمصادر الرقمية (Forensic Artifacts) الخاصة بكل سؤال، عشان تقدر تضيفهم مباشرة في ملف الـ README.md الخاص بالـ Writeup بتاعك:

🔍 VulnOS v2 - Complete Walkthrough & Forensic Analysis
📌 Part 1: System & Network Artifacts (Q1 - Q7)
Q1: What is the system timezone?

Answer: Europe/Brussels

Forensic Source: تم التحقق منه عن طريق قراءة ملف النظام /etc/timezone أو فحص الـ Symlink للمسار /etc/localtime.

Q2: Who was the last user to log in to the system?

Answer: mail

Forensic Source: من تحليل سجلات الدخول في ملف /var/log/auth.log أو قراءة ملف /var/log/lastlog و /var/log/wtmp.

Q3: What was the source port the user 'mail' connected from?

Answer: 57708

Forensic Source: مأخوذة من السطر الخاص بجلسة الـ SSH المفتوحة للمستخدم mail داخل /var/log/auth.log (بنسق: sshd[PID]: Accepted password for mail from <IP> port 57708 ssh2).

Q4: How long was the last session for user 'mail'? (Minutes only)

Answer: 1

Forensic Source: تم حساب الفارق الزمني بين حدث فتح الجلسة (session opened) وإغلاقها (session closed) الخاص بـ sshd داخل /var/log/auth.log.

Q5: Which server service did the last user use to log in to the system?

Answer: sshd

Forensic Source: خدمة الـ Secure Shell التي قامت بمعالجة عملية المصادقة وتسجيلها في السجلات.

Q6: What type of authentication attack was performed against the target machine?

Answer: Brute-force

Forensic Source: ظهرت في السجلات محاولات إدخال كلمات سر خاطئة متكررة ومكثفة (Failed password for ...) متتالية خلال فترة زمنية قصيرة قبل النجاح في الدخول.

Q7: How many IP addresses are listed in the /var/log/lastlog file?

Answer: 2

Forensic Source: تحليل العناوين المسجلة داخل الملف الثنائي /var/log/lastlog.

👤 Part 2: Accounts & Privilege Escalation (Q8 - Q14)
Q8: How many users have a login shell?

Answer: 5

Forensic Source: فحص ملف /etc/passwd وعد الحسابات التي تمتلك Shell تفاعلي (مثل /bin/bash أو /bin/sh) واستبعاد الحسابات الخاصة بالخدمات (/sbin/nologin أو /bin/false).

Q9: What is the password of the mail user?

Answer: forensics

Forensic Source: تم الوصول إليها عبر فك تشفير الـ Hash الخاص بالمستخدم في ملف /etc/shadow أو العثور عليها مكتوبة في ملفات الإعدادات/الهستوري.

Q10: Which user account was created by the attacker?

Answer: php

Forensic Source: تم التعرف عليه من خلال فحص تاريخ إنشاء الحسابات في /etc/passwd وسجلات تنفيذ أمر useradd/adduser في /var/log/auth.log.

Q11: How many user groups exist on the machine?

Answer: 59

Forensic Source: تم الاستعلام عنها بعدد الأسطر المسجلة داخل ملف مجموعات النظام /etc/group.

Q12: How many users have sudo access?

Answer: 2

Forensic Source: تم استخراجها من ملف /etc/sudoers وأعضاء مجموعة sudo أو wheel داخل /etc/group.

Q13: What is the home directory of the PHP user?

Answer: /var/php

Forensic Source: المسار المسجل في الحقل السادس لقيد المستخدم php داخل ملف /etc/passwd.

Q14: What command did the attacker use to gain root privilege?

Answer: sudo su -

Forensic Source: تم رصد الأمر المستخدم للتصعيد الشامل للصلاحيات داخل سجل الأوامر .bash_history أو سجلات الـ Sudo في /var/log/auth.log.

🧪 Part 3: Anti-Forensics, Exploits & Web CMS (Q15 - Q19)
Q15: Which file did the user 'root' delete?

Answer: 37292.c

Forensic Source: تم العثور على أمر الحذف rm 37292.c أثناء فحص ملف سجل الأوامر /root/.bash_history.

Q16: Recover the deleted file, open it and extract the exploit author name.

Answer: rebel

Forensic Source: بعد استرجاع الملف من الـ Unallocated Space أو البحث في الـ Strings، تبين أن الثغرة هي (OverlayFS Local Privilege Escalation - CVE-2015-1328) وتحتوي في الـ Header على اسم المطور rebel.

Q17: What is the content management system (CMS) installed on the machine?

Answer: drupal

Forensic Source: تم التعرف عليه من هيكل مجلدات الموقع في /var/www/html/ وسجل الأوامر الخاص بالمستخدم vulnosadmin.

Q18: What is the version of the CMS installed on the machine?

Answer: 7.26

Forensic Source: تم استخراج رقم الإصدار من ملف الإعدادات الرئيسي للـ CMS في المسار /var/www/html/includes/bootstrap.inc أو ملف CHANGELOG.txt.

Q19: Which port was listening to receive the attacker's reverse shell?

Answer: 4444

Forensic Source: تم العثور على البورت المسجل في أوامر الاتصال العكسي (مثل nc / netcat) أو إعدادات السكريبتات الخبيثة في سجل الأوامر.
