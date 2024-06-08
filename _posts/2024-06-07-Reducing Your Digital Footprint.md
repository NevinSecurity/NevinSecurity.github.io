# What is a Digital Footprint and why is it important?

### A digital footprint – sometimes called a digital shadow or an electronic footprint – refers to the trail of data you leave when using the internet. It includes websites you visit, emails you send, and information you submit online. A digital footprint can be used to track a person's online activities and devices 
ref: [Kaspersky](https://usa.kaspersky.com/resource-center/definitions/what-is-a-digital-footprint#:~:text=A%20digital%20footprint%20%E2%80%93%20sometimes%20called,person%27s%20online%20activities%20and%20devices.)

Reducing your digital footprint isn't only beneficial to your employer's security, it can help protect you or your loved ones. Every digital asset you own, including your identity, can be stolen by hackers. It is even more devistating learning that most of the time, not even the government can help you get your funds returned. 

No system is impervious to hacking, much like a castle is never completely immune to infiltration. However, just as a fortified castle has multiple layers of defenses; moats, walls, gates, and guards, effective cybersecurity relies on implementing various layers of protection. Each layer adds strength to the overall defense, making it more difficult for adversaries to breach the system and minimizing the potential damage if they do.

There are many different attacks that hackers can use to steal from individuals, but here are a few that you can soon be a pro at blocking:  

<br>

* **Phishing**: Trickery through fake emails or messages, pretending to be trustworthy sources, to steal personal information or login credentials.

* **Pig Butchering / Catfishing**: Creating fake online personas to deceive others into romantic relationships or financial scams.

* **Tech Support Scams / Gift Card Scams**: Pretending to be tech support or offering fake prizes, then tricking victims into providing money or gift card codes for supposed fixes or rewards.

* **Password Reuse Attacks**: Exploiting the use of the same password across multiple accounts to gain unauthorized access to sensitive information or services.

* **Identity Theft**: Stealing personal information, such as Social Security numbers or credit card details, to impersonate individuals for financial gain or fraudulent activities.

* **Baiting**: Tempting individuals with enticing offers or promises to lure them into compromising situations, such as clicking on malicious links or downloading infected files.

<br>

### Basic Layers For Digital Privacy and Security

Here are some of the layers that, if implemented, can drastically increase your security and reduce your digital footprint.
* Use MFA where ever possible.
* Slow down; read your hyperlinks and error messages
* Change breached email account’s passwords.
* Use a password manager.
* Limit your exposure.
* Use multiple email addresses.
* Use alternate aliases.

<br>

### Use MFA where ever possible.
First and foremost, it is extremely important to setup multi-factor authentication (MFA, or sometimes 2FA) where ever possible. This is the little code or push notification that you get while logging in to prove it's really you. Although it can be slightly annoying, it drastically increases the security of accounts. This will likely be the single, most beneficial step to secure you. This will always be available for your email, bank, and social media accounts. It can prevent someone getting into your account if you have weak passwords, or have reused passwords that have been breached in the past.

<br>

### Slow down; read your hyperlinks and error messages.

Speaking of previously breached passwords, a great website to use when determining the most recent data leak that applies to you, is https://haveibeenpwned.com/.

Your first thought may be "Clicking on a link? Yeah right, nice try!", and if it is, then that's awesome! Being skeptical of what you click is always a staple to being safe online. 
Sometimes that means slowing down and making sure to read everything, before clicking. Some links, known as [hyperlinks](https://en.wikipedia.org/wiki/Hyperlink#:~:text=In%20computing%2C%20a%20hyperlink%2C%20or,specific%20element%20within%20a%20document.), can change the text of the link, and even trick you into thinking you're going somewhere else. To counter this, hovering over a link can show you where it will actually be taking you. Always look for the Domain Name, and the Top Level Domain (TLD) in the link. You likely already do this, but this is essentially the website you'll be redirected to. For example, in the link: 

[cloud.outlook.microsoft.gethacked.com](https://www.youtube.com/watch?v=dQw4w9WgXcQ)

The Domain is "gethacked", and the TLD is ".com". The real domain, or website name, is always before the last period. Don't be fooled by people who add other real domain names to their subdomains like the latter example. It's also important to watch out for typosquatting. "A TypoSquatting attack takes advantage of instances where a user mistypes a URL (e.g. www.goggle.com) or does not visually verify a URL before clicking on it (e.g. phishing attack)" [MITRE](https://capec.mitre.org/data/definitions/630.html).


For someone who wants more validation of what a website is before clicking, for instance https://haveibeenpwned.com, it may be better to instead Google "haveibeenpwned" without the TLD, ".com". If there is no other information about the website, or a wikipedia article about it, you may need to input the URL to a tool like [Virus Total](https://www.virustotal.com/gui/home/url). This tool will check the website for malware and let you know if traveling there will be safe. If the website is still suspicious upon entering, it's possible that Virus Total only scanned the landing page of the website. Be cautious when exploring the internet with every click.

Far too many people get in the habit of clicking close or exit when encountered with popups. It's always a good idea to slow down and read them, because sometimes the solution to the popup is right in the error text.

<br>

### Change breached email account's passwords.
  https://haveibeenpwned.com is amazing for checking to see if your email has been breached and what service it was breached through. 

Most emails older than a few years have been involved in at least one of these breaches. If you see your email was breached, it may be best to change your password if you haven't changed it since the date of the breach.

<br>

### Use a password manager.

When it comes to picking secure passwords, most people prefer shorter, easier to type passwords, because it prevents them from being annoyed each time they are logging in. I highly recommend at least using 14 characters, and 20 or more if you're up to the challenge. Using a passphrase, or a combination of words can help you easily reach these characters limits. I typically recommend at least stringing together three words with symbols, numbers, and various capitals. 

The strongest strength a password has is it's length, as it makes it significantly longer to brute force a password. For instance, an 8 character password could be bruteforced in a day if you happen to get lucky, but a 20 character password could take up to 5,700,000,000,000,000,000,000 years to bruteforce! That's a lot of time! 

Password spraying is a type of brute force attack where an attacker attempts to access multiple user accounts by trying a small number of commonly used passwords against many accounts [OWASP](https://owasp.org/www-community/attacks/Password_Spraying_Attack). Unlike traditional brute force attacks that try many passwords against a single account, password spraying tries a few passwords against many accounts, making it less likely to trigger account lockout mechanisms.

By using commonly used passwords, attackers can efficiently try a large number of passwords across many accounts in a short amount of time.

*The easiest way to prevent most of these password attacks is to use a password manager.* Password managers are a rare occurance of when an increase in security is also more convenient. When used correctly, you can be immune to password spraying, dictionary attacks, password reuse attacks, and more. Password managers allow you to generate and store completely randomized 20+ character passwords, while only needing to remember a single password to access your vault of saved credentials. It's not uncommon for people to save dozens or even hundreds of credentials within password managers. 

To take it a step further, some password managers have browser extensions that will autofill your credentials, which can help mitigate entering your credentials in a phishing attempt. If your password doesn't autofill like normal, you may be on a different website than you thought you were on. This gives you a clue to check the URL and confirm it's not a malicious domain.

<br>

### Limit your exposure.

If you're constantly posting to social media, it may be a good idea to stagger the content you post instead of posting it in the moment. This can help prevent others from knowing exactly where you are and can prevent things like stalking.

You can also limit your exposure to hacks by being cautious about what tech you use at home. If you use third-party security systems in your own home, they might already be compromised!
[During Ring Doorbell's security incidents in 2023](https://www.ftc.gov/news-events/news/press-releases/2023/05/ftc-says-ring-employees-illegally-surveilled-customers-failed-stop-hackers-taking-control-users), hackers would look for people who had recently left their property before breaking in. There were multiple accounts of this occurring, along with porch pirates erasing footage of the crime scene ([source](https://community.ring.com/t/porch-thief-hacked-in-and-erased-doorbell-video-of-the-crime/2695)).

Reducing the amount of [IoT devices](https://builtin.com/articles/iot-devices), or internet connected devices, at home could prevent a break in. However, it's much more common to expose your data through a website or social media platform. 

* Quick Tip: I always recommend using the add blocker, [Ublock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm?hl=en), in order to reduce adds and the likeliness that you'll click on a malicious link or popup when browsing.

It is also a good idea to reduce the exposure of your social media accounts by vetting your friendlist, and changing your privacy settings to prevent leakage of identifying data. The most common identifiable data is your phone number and email address. 

<br>

### Use multiple email addresses.

Most people already have a few emails. Some they use for junk, and some they use for banking. Using a service like [SimpleLogin](https://simplelogin.io/) along side a password manager can make it easy to split your online exposures into multiple identities. This makes it more difficult for companies or hackers to collect data on you. 
* As a reminder, it's important to protect your data from companies because they don't always do a great job at securing your data from hackers.

In a healthcare dataleak, it will likely relate your healthcare information back to your name, email, phone number, or social security number ([SSN](https://www.youtube.com/watch?v=Erp8IAUouus)). However, with most data leaks, your account may be primarly linked to your email address or phone number as a means of identification.  In turn, email addresses and phone numbers are extremely valuable information for companies that [collect data for profit](https://www.knowledge-sourcing.com/report/global-data-broker-market), which is likely most websites you use. These companies will say the collection of your data is safe, because it's deanonymized. However, it doesn't ever really end up being deanonymized, as it will typically contain enough data to easily identify you.

Since it is more difficult to obtain multiple phone numbers, it's recommended to treat your phone number as you would your [SSN](https://www.youtube.com/watch?v=Erp8IAUouus) and to use multiple email addresses if you want to limit your exposure, without reducing your online usage. Using a service for this may seem overkill, but you'd be surprised at how effective it is in reducing spam emails, spam calls, and your digital footprint. 

<br>

### Use alternate aliases.

For some, like content creators, being recognized is extremely important towards your earnings and reputation. But for a digital privacy enthusiast, it's best to use different aliases if given an option. For instance, having your Social Media usernames be unique can easily prevent people from collecting more unwilfully provided information about you.

In some cases like applying for jobs, so much of your private information is exposed. Some even include phone numbers, addresses, and emails all within their resume that they upload to multiple websites. Beyond your contact information, valuable data about your career and studies can be used to socially engineer you. Many adversaries use resume databases for information about specific targets, especially if their target has elevated access (see [MITRE T1589.002](https://attack.mitre.org/techniques/T1589/002/)). Using a Preferred Name is one way to drastically reduce the amount of personal information that you'll have exposed. It's important to let them know your real identity if they're to perform a background check on you, as you're not trying to hide from them, just the resume databases.
<br>

*While this may sound pretty extreme, it's generally a good idea to not trust internet strangers with important data if you can help it.* 
<br>

This ensures your data isn't over exposed by recruiters to resume databases that may be unmanaged and insecure. Do not try this if you're applying to government positions as it could come across as ill intent. 

While some employers may not agree, it ultimately increases your security for you and your new employer. It's possible that some employers may instantly dismiss your application due to feeling tricked, but it's much more accepting in companies with positive cybersecurity culture. These environments tend to be much more appealing to work for anyway, so it can act as a filter if you're interested in security-conscious companies.

<br>

*A firefighter may have more safegaurds for preventing fires in their own home, like three fire extinguishers and fire alarms, because they fight fire on a regular basis. This might seem weird to someone who might only have one, but firefighters are constently reminded of the destruction that fire is capable of.* 

<br>

Reducing your online footprint is a practice of personal data security which directly translates into enterprise data security. Data security professionals that don't practice reducing their online footprint can be ripe for malicious advisaries to target. This is due to prevelance of collecting Open Source Intelligence, or OSINT, for reconnaissance. Shown in the [previously linked MITRE framework](https://attack.mitre.org/techniques/T1589/), gathering your victims identity information is a commonly performed technique in the first step of hacking an enterprise. Being able to directly limit the amount of information that is exposed about you on the internet can return dividens to you and your future employers. 

<br>

<br>

### In Conclusion

There is no single button or product that can prevent you from being hacked, as it requires multiple layers of protection. Once you have your castle walls, trench, moat, and draw-bridge ready, you'll be ready to defend yourself against some of the most devistating hacks.

I hope you've enjoyed some basic layers that you could implement yourself to start increasing your security and reduce your digital footprint. Have fun browsing the web, and be careful what you click.