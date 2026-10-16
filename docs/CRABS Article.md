# An Agreement, Not an App

### A gentle guide to CRABS — the quiet invention that could end the era of digital landlords

For about a decade now, if you wanted to build software that nobody owns — a social network that isn't Facebook's, a video platform that isn't YouTube's, a group ledger that isn't a bank's — you were told there were two options.

**Option one:** rent everything. Your app lives on a company's servers, under a company's rules, surviving at a company's pleasure. Every user is a tenant. Every tenant can be evicted.

**Option two:** cryptocurrency. Put your app on a blockchain, pay fees for every action, and join a global computer whose whole design orbits around money. Want to vote on something? That's a transaction. Want to store something? Rent space from strangers who are paid in tokens to maintain a shared spreadsheet.

Both options share an unspoken assumption: that software owned by *nobody* must be owned by *something bigger than everybody* — a company, or a market.

In 2026, an open-source project called **CRABS** quietly broke that assumption. And the strange thing about it is how boring it looks.

---

## The realization: apps don't need a bank

Start with an honest inventory. What does an app actually need?

- **Memory** — a record of what's true: who joined, who paid, what was posted, what's finished.
- **Rules** — who's allowed to do what: members can post, admins can remove, only the treasurer can move money out.
- **Sharing** — the same truth visible to everyone in the group, updated live, even when people are in different places or briefly offline.
- **Timing** — things that happen at 5pm, or every Monday, or only after enough people agree.
- **Accountability** — proof of who did what, that can't be quietly rewritten later.

That's the whole list for the overwhelming majority of apps — book clubs and PTA fundraisers, clinics and co-ops, classrooms and fandoms, guilds in games and moderation teams on forums. Notice what isn't on the list: *money markets*. What people need from apps, most of the time, isn't finance. It's coordination.

The crypto era got this backwards. It built a magnificent, expensive machine for moving value — and then insisted every *other* purpose ride on top of it, paying tolls. Every shared to-do list had to be a financial instrument. Every vote, a transaction with a fee. And every app built on the same chain shared the same fate: when the chain had trouble, *everything* on it had trouble. **A library should not shut down because someone robbed the bank.** In the old architecture, it had no choice — the library *was inside* the bank.

CRABS starts from the inventory instead. It turns out that when you build exactly what apps need — and nothing else — you can do something remarkable: the app stops being property entirely.

---

## What CRABS actually is: three boring things, glued together

Strip away the acronym, and CRABS is an app's memory with three superpowers bolted on.

**First, it's a shared notebook.** Every person in the group runs the app — in their browser, on their laptop, on their phone. Everyone holds the same notebook: the members, the rules, the records. Nobody holds the *original*, because there is no original. There are only synchronized copies. (If you've ever watched two people edit a Google Doc at the same time and seen the document merge cleanly — congratulations, you've already used the merge mathematics CRABS is built on. That trick, which lets copies drift apart during a dropped connection and knit back together without a boss, is half of CRABS.)

**Second, every change is signed.** When you add something to the notebook, your signature goes with it — a cryptographic signature, the kind that can't be forged. And the notebook checks *permission* the same way: rules in the group's own rulebook decide who may do what, and the rulebook enforces itself. There's no bouncer at the door; the door itself knows who's allowed through. You can even prove you're allowed *without revealing who you are* — "someone with moderator status flagged this" is expressible as a fact — so privacy and accountability stop being opposites.

**Third, the notebook enforces its own history.** Every change is recorded in a tamper-evident chain of entries, like a diary whose pages would tear if anyone tried to rewrite them. Rules can even *react* to the notebook automatically: when enough flags accumulate on a video, a moderator can be granted time-limited access to the uploader's contact info — no human in the loop, no administrator to trust, the escalation written as a rule agreed to in advance. And things can be scheduled: a payment due on the 1st, a recurring election every Monday — recorded, executed at the right moment, exactly once, with the audit trail to prove it.

That's it. A shared notebook. Signatures. Self-enforcing rules. **The inventor's own description is disarming in its simplicity: "I attached cryptography to an app's memory. Keep it simple."**

It runs anywhere — the entire machinery compiles into a small module that loads in a web browser, the same way a website loads. Install it like any software library, and a group of friends, with no servers, no company, and no cryptocurrency, can share a state that remembers, rules that enforce, and a history that can't be quietly edited. Two browser tabs on two machines become peers. If one is offline for a week, it catches up when it returns, and the copies reconcile.

---

## Why this matters more than it sounds

**The apps people use stop being companies.** A video platform built this way isn't a YouTube competitor with different branding — it's a different *species*. The views counter is owned by nobody and can't be inflated by a server-side tweak. The moderation rules are public state. The uploader's contact info is sealed under rules the group wrote, not under a privacy policy a corporation can revise. Nobody can shut the platform down, because there's nothing to shut down — it exists wherever its users are.

**Groups get infrastructure without becoming customers.** A union local, a housing co-op, a patient group, a school's parents' association: today their digital tools are either spreadsheets emailed around or free tiers of someone's platform, where the real product is the group's data. With shared, signed, self-enforcing state, a group of twelve people can have what previously required an institution — treasury rules, one-vote-per-member elections, role-based access, an audit trail — as a file that lives on their own devices.

**And here is the subtle one: voting stops being a promise and becomes a fact.** In most software, "one vote per person" is enforced by whatever code happens to be running — changeable, bypassable, invisible when violated. In CRABS, one-vote-per-person is a property of the state itself. The second vote doesn't fail because an app decided it should; it fails because the notebook, held by everyone, remembers. Elections without a landlord. Treasuries without a bank. Rules that survive their authors' servers — because there are no authors' servers.

There's one more move worth knowing about, because it's the growth mechanism: **groups can create groups.** A machine — the notebook plus its rules — can mint another machine and hand it narrowed powers: a subgroup that can manage its own forum but can never touch the treasury, a chapter of an organization that inherits the parent's identity rules but not its spending rules. Powers can narrow as they descend; they can never widen. This is the structure of organizations — charter to chapter to committee — expressed as pure cryptography, without a headquarters in sight.

---

## The honest part

No honest article skips this section.

**The hardest problem wasn't solved by CRABS; it was correctly refused.** "One person one vote" assumes you can tell people apart. Proving unique personhood — without a central ID issuer, and against someone motivated to fake it — remains unsolved, in CRABS as everywhere. CRABS is honest about this: it takes the question of *who counts as a person* out of the substrate and hands it to the group's own enrollment policy, where it becomes explicit rules instead of hidden defaults.

**Trust didn't vanish; it moved and shrank.** Every CRABS system is bootstrapped by a master cryptographic key held by the software's developers — much as every secure website's padlock ultimately traces back to a handful of browser-trusted certificate authorities. That's a far smaller throne than a platform's, and the architecture is built to shrink it further (the key's powers are deliberately limited, swappable, and audit-visible), but it is a real trust, and the project says so out loud.

**And the cryptography is heavy — for now.** The elegant lock-and-seal math at CRABS's heart is computationally expensive, taking seconds where ordinary encryption takes milliseconds. The design anticipated this: the cryptographic parts are pluggable, swappable as better schemes mature — including, when they're ready, schemes that survive quantum computers.

This honesty is itself a signal. Nothing here is hiding its edges. The design documents discuss the failure modes in public, by name, with test cases.

---

## The door this opens

The internet's original promise was peer-to-peer: every computer a peer, every user a *person*, not an account on someone's machine. That promise got interrupted — first by the platform era, which made us all tenants, and then by the crypto era, which heard "decentralization" and answered with financial markets, tolls, and speculation.

What CRABS demonstrates is that the interruption was never about technology. Decentralized apps were expensive and rare because we kept trying to build them on top of money. Take the money out — because it was never what apps needed — and the expense falls away. **When building an app that nobody owns costs the same as building an app that somebody does, people will build the free one without being persuaded to.** The tool does the teaching.

An app built this way is not a product. It's not even a place. It's an agreement — written down, signed, enforced by its own rules, held by everyone who lives inside it, and owned by none of them.

Hard shell. Sharp pincers. No backdoors.

---

*For the technically curious:* CRABS unifies three long-studied ideas — attribute-based encryption (envelopes that open only for holders of the right roles, without the sender knowing recipients in advance), conflict-free replicated data types (the Google Docs merge trick), and protocol state machines (rules expressed as enforceable state transitions). It's open source, runs as a standard web module, and its full specification — six formal amendments of test vectors and security analyses — is public.


