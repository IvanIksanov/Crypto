// script.js

// Утилиты для конвертации ArrayBuffer в строки для логов
function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

// Добавляет текст в общий лог с меткой времени
function log(msg) {
  const logEl = document.getElementById("logShared");
  const li = document.createElement("li");
  li.innerText = `${new Date().toLocaleTimeString()}: ${msg}`;
  logEl.appendChild(li);
  logEl.scrollTop = logEl.scrollHeight;
}

let publicKeyA_RSA, privateKeyA_RSA, publicKeyA_SIGN, privateKeyA_SIGN;
let publicKeyB_RSA, privateKeyB_RSA, publicKeyB_SIGN, privateKeyB_SIGN;

// Генерация ключей для пользователей A и B
(async () => {
  log(">>> Инициализация: старт генерации криптографических ключей для A и B.");

  // A — шифрование RSA-OAEP
  const rsaA = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["encrypt","decrypt"]
  );
  publicKeyA_RSA = rsaA.publicKey;
  privateKeyA_RSA = rsaA.privateKey;
  log("A: сгенерирована пара ключей RSA-OAEP (шифрование/дешифрование).");

  // A — подпись RSASSA-PKCS1-v1_5
  const signA = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["sign","verify"]
  );
  publicKeyA_SIGN = signA.publicKey;
  privateKeyA_SIGN = signA.privateKey;
  log("A: сгенерирована пара ключей RSASSA-PKCS1-v1_5 (подпись/проверка).");

  // B — шифрование RSA-OAEP
  const rsaB = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["encrypt","decrypt"]
  );
  publicKeyB_RSA = rsaB.publicKey;
  privateKeyB_RSA = rsaB.privateKey;
  log("B: сгенерирована пара ключей RSA-OAEP (шифрование/дешифрование).");

  // B — подпись RSASSA-PKCS1-v1_5
  const signB = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true,
    ["sign","verify"]
  );
  publicKeyB_SIGN = signB.publicKey;
  privateKeyB_SIGN = signB.privateKey;
  log("B: сгенерирована пара ключей RSASSA-PKCS1-v1_5 (подпись/проверка).");

  log(">>> Завершена генерация всех ключей для A и B.");
})();

// Отправка сообщения из A в B
async function sendMessageA() {
  const text = document.getElementById("inputA").value.trim();
  if (!text) return;
  document.getElementById("inputA").value = "";

  log(`A: подготовка к отправке. Plaintext="${text}"`);
  const packet = await preparePacket(text, publicKeyB_RSA, privateKeyA_SIGN, "A");

  appendMessage("chatA-messages", text, "right");
  log("A: пакет сформирован (AES+RSA+подпись), передаю в сеть → B.");
  simulateNetworkTransfer(packet, "A→B");
}

// Отправка сообщения из B в A
async function sendMessageB() {
  const text = document.getElementById("inputB").value.trim();
  if (!text) return;
  document.getElementById("inputB").value = "";

  log(`B: подготовка к отправке. Plaintext="${text}"`);
  const packet = await preparePacket(text, publicKeyA_RSA, privateKeyB_SIGN, "B");

  appendMessage("chatB-messages", text, "right");
  log("B: пакет сформирован (AES+RSA+подпись), передаю в сеть → A.");
  simulateNetworkTransfer(packet, "B→A");
}

// Формируем "пакет": симметричное шифрование + шифрование ключа + цифровая подпись
async function preparePacket(plaintext, recipientPubKey, senderPrivSign, who) {
  // 1) Генерация AES-GCM ключа и IV
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt","decrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  log(`${who}: сгенерирован AES-GCM ключ и IV (IV hex=${arrayBufferToHex(iv)}).`);

  // 2) Шифрование текста AES-GCM
  const encData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(plaintext)
  );
  log(`${who}: AES-GCM зашифровал данные (ciphertext base64=${arrayBufferToBase64(encData)}).`);

  // 3) Экспорт AES ключа и его RSA-OAEP шифрование
  const rawAes = await crypto.subtle.exportKey("raw", aesKey);
  log(`${who}: экспорт raw AES ключа (hex=${arrayBufferToHex(rawAes)}).`);
  const encKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPubKey,
    rawAes
  );
  log(`${who}: RSA-OAEP зашифровал AES ключ (cipher key base64=${arrayBufferToBase64(encKey)}).`);

  // 4) Подпись зашифрованных данных RSASSA-PKCS1-v1_5
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    senderPrivSign,
    encData
  );
  log(`${who}: сгенерирована цифровая подпись (base64=${arrayBufferToBase64(signature)}).`);

  return { encryptedData: encData, iv, encryptedKey: encKey, signature };
}

// Симуляция сетевой задержки и передачи
function simulateNetworkTransfer(packet, direction) {
  log(`Сеть: начало передачи пакета ${direction}.`);
  setTimeout(() => {
    log(`Сеть: пакет ${direction} доставлен.`);
    if (direction === "A→B") receiveMessageB(packet);
    else receiveMessageA(packet);
  }, 800);
}

// Прием и распаковка пакета на стороне B
async function receiveMessageB(packet) {
  log("B: получен пакет, начинаю распаковку.");
  const { msg, verified } = await unpackPacket(packet, privateKeyB_RSA, publicKeyA_SIGN, "B");
  appendMessage("chatB-messages", msg, "left");
  log(`B: распаковка завершена. Plaintext="${msg}", подпись валидна=${verified}.`);
}

// Прием и распаковка пакета на стороне A
async function receiveMessageA(packet) {
  log("A: получен пакет, начинаю распаковку.");
  const { msg, verified } = await unpackPacket(packet, privateKeyA_RSA, publicKeyB_SIGN, "A");
  appendMessage("chatA-messages", msg, "left");
  log(`A: распаковка завершена. Plaintext="${msg}", подпись валидна=${verified}.`);
}

// Расшифровка AES ключа, проверка подписи и дешифрование содержимого
async function unpackPacket(packet, privRSA, senderPubSign, who) {
  const { encryptedData, iv, encryptedKey, signature } = packet;

  // 1) RSA-OAEP дешифровка AES ключа
  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privRSA,
    encryptedKey
  );
  log(`${who}: RSA-OAEP дешифровал AES ключ (hex=${arrayBufferToHex(rawKey)}).`);

  // 2) Импорт AES ключа
  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  log(`${who}: импортирован AES ключ для дешифрования.`);

  // 3) Проверка цифровой подписи
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      senderPubSign,
      signature,
      encryptedData
    );
    log(`${who}: проверка подписи RSASSA завершена: валидно=${verified}.`);
  } catch (e) {
    log(`${who}: ошибка проверки подписи: ${e}`);
  }

  // 4) AES-GCM дешифрование данных
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encryptedData
  );
  const msg = new TextDecoder().decode(decrypted);
  log(`${who}: AES-GCM дешифровал данные, получен Plaintext="${msg}".`);

  return { msg, verified };
}

// Добавляет сообщение в окно чата
function appendMessage(containerId, text, alignment) {
  const container = document.getElementById(containerId);
  const div = document.createElement("div");
  div.className = `message ${alignment}`;
  div.innerText = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}