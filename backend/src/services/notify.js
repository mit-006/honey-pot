// Optional email delivery. Without SMTP_URL nothing is sent (the in-app notification feed is always written).
export function createNotifier(config) {
  let transport = null;
  let tried = false;

  async function getTransport() {
    if (transport || tried || !config.smtpUrl) return transport;
    tried = true;
    try {
      const nodemailer = (await import('nodemailer')).default;
      transport = nodemailer.createTransport(config.smtpUrl);
    } catch (e) {
      console.warn('[notify] nodemailer unavailable, email disabled:', e.message);
    }
    return transport;
  }

  return {
    configured: Boolean(config.smtpUrl),
    async sendEmail(to, subject, text) {
      if (!to.length) return false;
      const t = await getTransport();
      if (!t) return false;
      try {
        await t.sendMail({ from: config.mailFrom, to: to.join(','), subject, text });
        return true;
      } catch (e) {
        console.warn('[notify] email failed:', e.message);
        return false;
      }
    },
  };
}
