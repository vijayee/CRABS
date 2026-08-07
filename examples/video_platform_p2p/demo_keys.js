'use strict';

// Demo-only key material. The mod1 account is shared between the browser
// client and the relay server so the ABE contact endpoint can authenticate
// the moderator without a real key-distribution step.

const MOD1_PRIVATE_KEY = 'd28485d7cf5ee1ac4d29eaf02d5683b8fb45e21aca3a0dfc94601bdb46b11134';

module.exports = { MOD1_PRIVATE_KEY };
