'use strict';

// Demo-only key material. These keys are shared between every browser tab and
// the relay server so that the same demo user is the same CRABS identity
// everywhere. This is purely for the example; a real app would never hard-code
// private keys.

const DEMO_KEYS = {
  alice: 'af91e876c3511e98b9ad26375abcc062e95f85677569c2bc95c1c834b78a4fc7',
  bob: 'f2861f728ec1846406b64e9344937511ad1df572c8134738f9b3d08418503c16',
  carol: 'fe88f2432fa7028b0c2219099ec8bf32c0fb5567164dbeb01065cdbaab71b662',
  mod1: 'd28485d7cf5ee1ac4d29eaf02d5683b8fb45e21aca3a0dfc94601bdb46b11134',
};

module.exports = { DEMO_KEYS };
