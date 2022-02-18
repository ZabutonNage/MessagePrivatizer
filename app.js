(async function () {
    if (!window.sodium) {
        window.sodium = await SodiumPlus.auto();
    }


    // ---- navigation stuff

    const pages = document.querySelectorAll(`.page`);
    const nav = document.querySelector(`nav`);

    nav.addEventListener(`click`, navigationHandler(`btn-gen`, `page-generate`));
    nav.addEventListener(`click`, navigationHandler(`btn-enc`, `page-encrypt`));


    function navigationHandler(buttonName, targetPageName) {
        return e => {
            if (!e.target.classList.contains(buttonName)) return;

            navigate(targetPageName);
        };
    }

    function navigate(pageName, data = {}) {
        const navButtons = nav.querySelectorAll(`button`);

        navButtons.forEach(btn => btn.disabled = btn.dataset.page === pageName);

        pages.forEach(page => {
            if (page.classList.contains(pageName) && !page.classList.contains(`hidden`)) return;

            page.querySelectorAll(`input, textarea`).forEach(input => input.value = ``);

            if (page.classList.contains(pageName)) {
                Object.keys(data).forEach(selector => page.querySelector(selector).value = data[selector]);

                page.querySelectorAll(`[data-defaults]`).forEach(element => {
                    const attrs = element.dataset.defaults.split(`,`);
                    attrs.forEach(attr => {
                        const [key, value] = attr.split(`=`);
                        element[key] = parseDefault(value);
                    });
                });

                page.classList.remove(`hidden`);
                page.querySelector(`[autofocus]`).focus();
            } else {
                page.classList.add(`hidden`);
            }
        });

        function parseDefault(value) {
            if (value === `$btrue`) return true;
            return value === `$bfalse`
                ? false
                : value;
        }
    }


    // ---- keygen page

    const pageKeygen = document.querySelector(`.page-generate`);
    const btnSubmitKeygen = pageKeygen.querySelector(`button[type=submit]`);
    const outputKey = pageKeygen.querySelector(`#out-public-key`);
    const btnCopyKey = pageKeygen.querySelector(`.copy-to-clipboard`);
    const btnGoToEnc = pageKeygen.querySelector(`#go-to-enc`);

    pageKeygen.querySelector(`#in-passphrase`).addEventListener(`input`, inputPassphrase);
    pageKeygen.querySelector(`form#generate-key`).addEventListener(`submit`, generateKey);
    btnCopyKey.addEventListener(`click`, copyTargetToClipboard);
    btnGoToEnc.addEventListener(`click`, toEncryptionWithPhrase);


    function inputPassphrase(e) {
        btnSubmitKeygen.disabled = e.target.value.length < 12;
        outputKey.disabled = true;
        outputKey.value = ``;
        btnCopyKey.disabled = true;
        btnGoToEnc.disabled = true;
    }

    async function generateKey(e) {
        e.preventDefault();

        const passphrase = pageKeygen.querySelector(`#in-passphrase`).value;

        const keyPair = await sodium.crypto_kx_seed_keypair(passphrase);
        const publicKey = await sodium.crypto_box_publickey(keyPair);

        outputKey.value = publicKey.toString(`hex`);
        outputKey.disabled = false;
        outputKey.focus();

        btnCopyKey.disabled = false;
        btnGoToEnc.disabled = false;
    }

    function toEncryptionWithPhrase() {
        const passphrase = pageKeygen.querySelector(`#in-passphrase`).value;
        navigate(`page-encrypt`, { "#in-passphrase-enc": passphrase });
    }


    // ---- encryption page

    const pageCrypto = document.querySelector(`.page-encrypt`);
    const sectionCryptoButtons = pageCrypto.querySelector(`#buttons-encrypt-decrypt`);
    const btnCopyCipherMsg = pageCrypto.querySelector(`.copy-to-clipboard`);

    const inputs = {
        encrypt: Array.from(pageCrypto.querySelectorAll(`.input.encrypt`)),
        decrypt: Array.from(pageCrypto.querySelectorAll(`.input.decrypt`)),
    };

    const getActionButton = mode => sectionCryptoButtons.querySelector(`[data-action="${mode}"]`);

    let mode = `encrypt`;
    let actionButton = getActionButton(mode);
    let oppositeMsgInput = document.querySelector(`#message-cipher`);

    pageCrypto.addEventListener(`input`, onCryptoInput);
    pageCrypto.querySelector(`#passphrase-show-hide`).addEventListener(`click`, togglePassphrase);
    pageCrypto.querySelector(`#message-cipher`)
        .addEventListener(`focus`, e => mode === `encrypt` && e.target.setSelectionRange(0, Number.MAX_SAFE_INTEGER));
    pageCrypto.querySelector(`#encrypt-message`).addEventListener(`click`, onEncryptClick);
    pageCrypto.querySelector(`#decrypt-message`).addEventListener(`click`, onDecryptClick);
    btnCopyCipherMsg.addEventListener(`click`, copyTargetToClipboard);


    function onCryptoInput(e) {
        const input = e.target;

        if (input.tagName === `TEXTAREA` && input.dataset.counterpart) {
            if (input.dataset.role !== mode) {
                mode = input.dataset.role;
                actionButton = getActionButton(mode);
                oppositeMsgInput = document.getElementById(input.dataset.counterpart);

                sectionCryptoButtons.classList.remove(`encrypt`, `decrypt`);
                sectionCryptoButtons.classList.add(mode);

            }

            oppositeMsgInput.value = ``;
            btnCopyCipherMsg.disabled = true;
        }

        // TODO highlight invalid inputs with red border or something

        actionButton.disabled = !inputs[mode].every(el => el.dataset.pattern
            ? el.checkValidity() && new RegExp(`^${el.dataset.pattern}$`).test(el.value)
            : el.checkValidity()
        );
    }

    function togglePassphrase(e) {
        const inputPassphrase = pageCrypto.querySelector(`#in-passphrase-enc`);
        inputPassphrase.type = e.target.innerText === `Show` ? `text` : `password`;
        e.target.innerText = e.target.innerText === `Show` ? `Hide` : `Show`;
    }

    function getRawKeysFromDOM() {
        return {
            recipientKeyHex: pageCrypto.querySelector(`#in-other-key`).value,
            passphrase: pageCrypto.querySelector(`#in-passphrase-enc`).value,
        };
    }

    async function onEncryptClick() {
        const rawKeys = getRawKeysFromDOM();
        const plaintext = pageCrypto.querySelector(`#message-clear`).value;

        const outputCipher = pageCrypto.querySelector(`#message-cipher`);

        try {
            outputCipher.value = await encryptMessage(rawKeys, plaintext);
            outputCipher.focus();
            btnCopyCipherMsg.disabled = false;
        } catch (ex) {
            console.error(ex);
            alert(`ERROR: ${ex.message}`);
        }
    }

    async function onDecryptClick() {
        const rawKeys = getRawKeysFromDOM();
        const cryptoMessage = pageCrypto.querySelector(`#message-cipher`).value;

        try {
            pageCrypto.querySelector(`#message-clear`).value = await decryptMessage(rawKeys, cryptoMessage);
        }
        catch (ex) {
            console.error(ex);
            alert(`ERROR: ${ex.message}`);
        }
    }

    async function encryptMessage(rawKeys, plaintext) {
        const { recipientPublicKey, ownSecretKey } = await importKeys(rawKeys);

        const nonce = await sodium.randombytes_buf(sodium.CRYPTO_BOX_NONCEBYTES);
        const nonceHex = nonce.toString(`hex`);

        const plaintextEncoded = new TextEncoder().encode(plaintext);

        const ciphertext = await sodium.crypto_box(plaintextEncoded, nonce, ownSecretKey, recipientPublicKey);
        const ciphertextHex = ciphertext.toString(`hex`);

        return nonceHex + ciphertextHex;
    }

    async function decryptMessage(rawKeys, cryptoMessage) {
        const { recipientPublicKey, ownSecretKey } = await importKeys(rawKeys);

        const nonceHex = cryptoMessage.substr(0, sodium.CRYPTO_BOX_NONCEBYTES * 2);
        const ciphertextHex = cryptoMessage.substr(sodium.CRYPTO_BOX_NONCEBYTES * 2);

        const plaintext = await sodium.crypto_box_open(
            await sodium.sodium_hex2bin(ciphertextHex),
            await sodium.sodium_hex2bin(nonceHex),
            ownSecretKey,
            recipientPublicKey
        );

        return plaintext.toString(`utf8`);
    }

    async function importKeys({ recipientKeyHex, passphrase }) {
        const recipientPublicKey = X25519PublicKey.from(await sodium.sodium_hex2bin(recipientKeyHex));

        const ownKeyPair = await sodium.crypto_kx_seed_keypair(passphrase);
        const ownSecretKey = await sodium.crypto_box_secretkey(ownKeyPair);

        return { recipientPublicKey, ownSecretKey };
    }


    // ---- common

    function copyTargetToClipboard() {
        const keyField = document.getElementById(this.dataset.target);
        keyField.select();
        keyField.setSelectionRange(0, Number.MAX_SAFE_INTEGER);

        navigator.clipboard.writeText(keyField.value);
    }
}());
