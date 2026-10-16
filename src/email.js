// Sends transactional email via Resend's HTTP API (https://resend.com) when
// RESEND_API_KEY is configured as a Worker secret. With no key set, this is a
// safe no-op — logged but never thrown — so that the password-reset and
// request-notification flows that call it never fail just because email
// hasn't been wired up yet. Swap the fetch target here if you'd rather use a
// different provider (SendGrid, Postmark, Cloudflare Email Routing, etc.) —
// callers only care about the {sent} boolean, not how it got there.
export async function sendEmail(env, { to, subject, html }) {
  if (!env.RESEND_API_KEY) {
    console.log("[email:skipped - no RESEND_API_KEY set]", to, subject);
    return { sent: false };
  }
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: env.RESEND_FROM || "PassFrame Portal <no-reply@passframe.co.uk>",
        to: [to],
        subject,
        html
      })
    });
    if (!res.ok) {
      console.log("[email:failed]", res.status, await res.text().catch(() => ""));
      return { sent: false };
    }
    return { sent: true };
  } catch (e) {
    console.log("[email:error]", e.message);
    return { sent: false };
  }
}
