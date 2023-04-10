// ==UserScript==
// @name        C.AI codec
// @namespace   Violentmonkey Scripts
// @match       https://2ch.hk/*
// @grant       none
// @version     1.0
// @author      meow
// @description 4/9/2023, 9:56:18 PM
// ==/UserScript==

const Crypto = window.crypto.subtle;
const encoder = new TextEncoder("utf-8");
const decoder = new TextDecoder("utf-8");
//
// Надежный план, Уолтер, отличный как швейцарские часы
// При необходимости придется поменять
// ну или пароль побольше придумать :yoba:
const iv = new Uint8Array(12);
const salt = new Uint8Array(16);

const buff_to_base64 = (buff) => btoa(String.fromCharCode.apply(null, buff));

const base64_to_buf = (b64) =>
  Uint8Array.from(atob(b64), (c) => c.charCodeAt(null));

const getPasswordKey = (password) =>
  Crypto.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveKey",
  ]);

const deriveKey = (passwordKey, salt, keyUsage) =>
  Crypto.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 250000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    keyUsage
  );

const encryptData = async (secretData, password) => {
  const passwordKey = await getPasswordKey(password);
  const aesKey = await deriveKey(passwordKey, salt, ["encrypt"]);
  const encryptedContent = await Crypto.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    encoder.encode(secretData)
  );

  const encryptedContentArr = new Uint8Array(encryptedContent);

  const base64Buff = buff_to_base64(encryptedContentArr);

  return base64Buff;
};

const decryptData = async (encryptedData, password) => {
  const data = base64_to_buf(encryptedData);

  const passwordKey = await getPasswordKey(password);
  const aesKey = await deriveKey(passwordKey, salt, ["decrypt"]);

  const decryptedContent = await Crypto.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    data
  );
  return decoder.decode(decryptedContent);
};

const webForm = `<div id="crypt-window" class="qr">
    <div class="qr__header" id="crypt-window-header">Шифровалка<span class="qr__close" id="qr-settings-window-close">X</span></div>
    <div class="qr__body settings">
        <form class="postform postform_qr">
            <div class="postform__raw postform__raw_flex">
                <input id="ia_password_input" autocomplete="new-password" class="postform__input postform__input_type_m input" type="password" placeholder="Пароль">
            </div>
            <div class="postform__raw postarea">
                <textarea id="ia_content_input" class="postform__input input" rows="10" placeholder="Ключики" tabindex="1" wrap="soft"></textarea>
            </div>
        </form>
      <div class="postform__raw" id="ia_codec_status" style="text-align: center"></div>
    </div>
    <div class="setting-buttons qr__footer">
        <hr>
        <input id="ia_encrypt_btn" type="button" class="button" value="Шифровать">
        <input id="ia_decrypt_btn" type="button" class="button" value="Расшифровать">
    </div>
</div>`;

const element = document.createElement("div");
element.innerHTML = webForm;
const closeBtn = element.querySelector("#qr-settings-window-close");
const pwdInput = element.querySelector("#ia_password_input");
const cntntInput = element.querySelector("#ia_content_input");
const encodeBtn = element.querySelector("#ia_encrypt_btn");
const decodeBtn = element.querySelector("#ia_decrypt_btn");
const windowSelf = element.querySelector("#crypt-window");
const status = element.querySelector("#ia_codec_status");

const triggerWindow = (isClosing) => {
  if (isClosing) {
    windowSelf.style.display = "none";
  } else {
    windowSelf.style.display = "block";
  }
};

closeBtn.onclick = () => triggerWindow(true);

encodeBtn.onclick = () => {
  encryptData(cntntInput.value, pwdInput.value)
    .then((result) => {
      cntntInput.value = result;
      status.innerHTML = "✔️ Успешно заныкано";
    })
    .catch((e) => {
      console.error(e);

      status.innerHTML = "❌ Произошла ужасная ошибка";
    });
};

decodeBtn.onclick = () => {
  decryptData(cntntInput.value, pwdInput.value)
    .then((result) => {
      cntntInput.value = result;
      status.innerHTML = "✔️ Успешно разныкано";
    })
    .catch((e) => {
      console.error(e);

      status.innerHTML = "❌ Поздравляем вас наебали 🤝";
    });
};

const mainBody = document.querySelector("body.makaba");

mainBody.appendChild(windowSelf);

draggable_qr("crypt-window", "center");

const formatterElement = $(".postform__raw .postform__mu-wrapper");

const modalCaller = document.createElement("button");

modalCaller.classList.add("postform__mu");
modalCaller.innerHTML = "🔐";
modalCaller.onclick = (e) => {
  e.preventDefault();
  triggerWindow(false);
};

formatterElement.append(modalCaller);
