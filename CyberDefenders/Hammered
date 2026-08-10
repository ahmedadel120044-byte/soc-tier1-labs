Hammered — Linux Log Forensics & Incident Response (CyberDefenders Write-Up)
تقرير تحليلي وتوثيق عملي للتحقيق الجنائي الرقمي للأنظمة (Linux Endpoint Forensics) على منصة CyberDefenders عبر تحليل ملفات الـ Logs المختلفة.

📌 نبذة عن اللاب (Overview)
يركز اللاب على تحليل حادثة اختراق كاملة لسيرفر Linux تم استهدافه بهجمات Brute-Force وتخطي الدفاعات. يعتمد التحليل على فحص أسلوب المهاجم بداية من الدخول غير المصرح به، مروراً بإنشاء الحسابات وتنزيل أدوات الفحص، وصولاً لتتبع ثغرات قواعد البيانات وقواعد الجدار الناري عبر مجموعة من سجلات النظام الموزعة (auth.log وkern.log وapache2/www-access.log وسجلات الـ Database).

🛠️ الأدوات المستخدمة (Tools Used)
Linux Command Line Interface (CLI): البيئة الأساسية لمعالجة وتحليل السجلات النصية.

Text Processing Utilities:

grep: للبحث عن الأنماط والنصوص المحددة داخل الملفات.

awk & cut: لاستخراج الخانات والبيانات المطلوبة من الأسطر.

sort & uniq: لتجميع ورصد البيانات المتكررة وحساب الأرقام الفريدة.

wc: لحساب عدد الأسطر والطلبات.

🔍 رحلة التحقيق والتحليل (Investigation Breakdown)
1. SSH Brute Force & Initial Compromise — auth.log
الهدف: كشف الخدمة المستهدفة للدخول، الحساب المخترق، وتتبع أثر المهاجمين عبر عناوين الـ IP.

الأوامر والفلترة:

فحص اتصالات SSH الناجحة:

Bash
grep "Accepted" auth.log
حصر عناوين الـ IP الفريدة التي نجحت في الدخول بعد محاولات فاشلة:

Bash
grep "Accepted" auth.log | awk '{print $11}' | sort -u | wc -l
معرفة أكثر IP قام بتسجيل الدخول بنجاح:

Bash
grep "Accepted" auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
استخراج وقت آخر دخول للـ IP المهاجم 219.150.181.20:

Bash
grep "219.150.181.20" auth.log | grep "Accepted" | tail -n 1
تتبع الحسابات الجديدة المنشأة بتاريخ 28 April الساعة 04:43:15:

Bash
grep "04:43:15" auth.log
النتائج:

Initial Service Used: SSH

Compromised Account: root

Successful Unique Attacker IPs: 6

Top Attacker IP: 219.150.181.20

Last Login Time (219.150.181.20): 2010-04-19 05:56

Created Persistence Account: wind3str0y

2. System Fingerprinting & Environment Identification
الهدف: تحديد إصدار نظام التشغيل المستهدف لمعرفة بيئة العمل المخترقة.

التحليل: فحص ملفات الحزم والتثبيت مثل dpkg.log للتعرف على معمارية وإصدار النواة والنظام.

النتائج:

OS Version: 4.2.4-1ubuntu3

3. Web Traffic Analysis — apache2/www-access.log
الهدف: رصد حجم الترافيك الموجه لسيرفر الـ Apache وكشف الـ Proxies والـ User-Agents المشبوهة.

الأوامر والفلترة:

حساب إجمالي طلبات الويب الموجهة للسيرفر:

Bash
wc -l apache2/www-access.log
فحص الـ User-Agents المستخدمة في عمليات الفحص:

Bash
awk -F'"' '{print $6}' apache2/www-access.log | sort -u
النتائج:

Total Apache Requests: 385

Proxy Scanner User-Agent: pxyscand/2.1

4. Firewall Inspection — kern.log
الهدف: معرفة التعديلات التي تمت على الجدار الناري وحساب عدد القواعد المضافة.

الأوامر والفلترة:

البحث عن أحداث إضافة قواعد الجدار الناري:

Bash
grep -i "ufw" kern.log | grep -i "rule" | wc -l
النتائج:

Added Firewall Rules: 6

5. Post-Exploitation & Database Security Audit
الهدف: تحديد أدوات الاستكشاف التي قام المهاجم بتحميلها وفحص التحذيرات الأمنية الخاصة بقواعد البيانات.

التحليل:

تتبع الأوامر والملفات المحملة للوصول لأداة الفحص الشبكي المستعملة.

مراجعة سجلات الـ Database لرصد الثغرات التشغيلية والإعدادات الخاطئة.

النتائج:

Downloaded Scanning Tool: nmap

Critical DB Warning: mysql.user contains 2 root accounts without password!

💡 أهم الدروس المستفادة (Key Takeaways)
التحليل المتقاطع (Cross-Log Correlation): ربط الأحداث بين auth.log وkern.log وسجلات الـ Web يمنحك الرؤية الكاملة لمراحل الهجوم (Kill Chain).

تأمين خدمات SSH: استخدام كلمة سر لحساب root يجعله عرضة للهجمات المباشرة؛ يفضل إلغاء تسجيل الدخول المباشر لـ root والاعتماد على SSH Keys.

سد ثغرات قواعد البيانات: وجود حسابات إدارية بدون كلمات مرور (No Password) يمثل نقطة ضعف خطيرة تمكن المهاجم من السيطرة الكاملة فور اختراق النظام.
