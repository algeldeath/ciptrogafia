
const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function hex(bytes, max = 24) {
  return Array.from(bytes.slice(0, max))
    .map(b => b.toString(16).padStart(2, "0"))
    .join(" ") + (bytes.length > max ? " …" : "");
}

function showStep(index, content) {
  const code = document.querySelectorAll(".step code")[index];
  if (code) code.textContent = content;
}

function resetSteps() {
  const defaults = [
    "Aguardando mensagem...",
    "Aguardando conversão...",
    "Aguardando derivação...",
    "Aguardando criptografia...",
    "Aguardando resultado..."
  ];

  defaults.forEach((value, i) => showStep(i, value));
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 310000,
      hash: "SHA-256"
    },
    material,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

function requireCrypto() {
  if (!window.crypto || !crypto.subtle) {
    throw new Error(
      "Este navegador não disponibilizou a API de criptografia. Abra o site em HTTPS ou em http://localhost."
    );
  }
}

// CRIPTOGRAFIA
$("encryptBtn").addEventListener("click", async () => {
  $("encryptError").textContent = "";
  $("decryptError").textContent = "";
  $("plainResult").classList.add("hidden");

  resetSteps();

  const message = $("message").value;
  const password = $("password").value;

  if (!message) {
    $("encryptError").textContent =
      "Digite uma mensagem antes de criptografar.";
    return;
  }

  if (password.length < 8) {
    $("encryptError").textContent =
      "Use uma chave com pelo menos 8 caracteres.";
    return;
  }

  const button = $("encryptBtn");
  button.disabled = true;
  button.textContent = "Processando...";

  try {
    requireCrypto();

    // 1. Converte o texto em bytes UTF-8
    const plainBytes = encoder.encode(message);

    // 2. Gera salt e IV aleatórios
    const salt = randomBytes(16);
    const iv = randomBytes(12);

    showStep(0, `Texto recebido: ${message.length} caractere(s).`);

    showStep(
      1,
      `${plainBytes.length} byte(s) UTF-8. Exemplo hexadecimal: ${hex(plainBytes)}`
    );

    // 3. Deriva a chave usando PBKDF2
    const key = await deriveKey(password, salt);

    showStep(
      2,
      `PBKDF2 • SHA-256 • 310.000 iterações • salt: ${bytesToBase64(salt)}`
    );

    // 4. Criptografa utilizando AES-256-GCM
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        key,
        plainBytes
      )
    );

    showStep(
      3,
      `AES-256-GCM • IV: ${bytesToBase64(iv)} • ${encrypted.length} byte(s) cifrados (inclui tag).`
    );

    // 5. Organiza os dados em JSON
    const packet = {
      algoritmo: "AES-256-GCM",
      derivacao: "PBKDF2-SHA-256",
      iteracoes: 310000,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      dados: bytesToBase64(encrypted)
    };

    const output = JSON.stringify(packet, null, 2);

    $("ciphertext").value = output;

    showStep(
      4,
      "Dados cifrados codificados em Base64. Pacote JSON com salt, IV e conteúdo."
    );

  } catch (error) {
    $("encryptError").textContent =
      error.message || "Não foi possível criptografar.";

  } finally {
    button.disabled = false;
    button.innerHTML = "<span>↗</span> Criptografar";
  }
});

// DESCRIPTOGRAFIA
$("decryptBtn").addEventListener("click", async () => {
  $("decryptError").textContent = "";
  $("encryptError").textContent = "";
  $("plainResult").classList.add("hidden");

  resetSteps();

  const password = $("password").value;

  if (!password) {
    $("decryptError").textContent =
      "Informe a mesma chave secreta usada na criptografia.";
    return;
  }

  let packet;

  try {
    packet = JSON.parse($("ciphertext").value);
  } catch {
    $("decryptError").textContent =
      "O pacote não é um JSON válido. Cole o pacote completo.";
    return;
  }

  if (
    !packet.salt ||
    !packet.iv ||
    !packet.dados ||
    packet.algoritmo !== "AES-256-GCM"
  ) {
    $("decryptError").textContent =
      "Pacote incompleto ou formato não reconhecido.";
    return;
  }

  const button = $("decryptBtn");
  button.disabled = true;
  button.textContent = "Processando...";

  try {
    requireCrypto();

    // 1. Recupera os dados do pacote
    const salt = base64ToBytes(packet.salt);
    const iv = base64ToBytes(packet.iv);
    const encrypted = base64ToBytes(packet.dados);

    showStep(
      0,
      "O pacote contém bytes cifrados; o texto original não fica visível nele."
    );

    showStep(
      1,
      `${encrypted.length} byte(s) recebidos e decodificados de Base64.`
    );

    // 2. Deriva novamente a chave
    const key = await deriveKey(password, salt);

    showStep(
      2,
      "Mesma senha + salt do pacote → PBKDF2 gera novamente a chave AES-256."
    );

    // 3. Descriptografa os dados
    const plainBytes = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        key,
        encrypted
      )
    );

    // 4. Converte os bytes novamente para texto
    const message = decoder.decode(plainBytes);

    showStep(
      3,
      "AES-GCM validou a tag de autenticação e recuperou os bytes originais."
    );

    showStep(
      4,
      `${plainBytes.length} byte(s) decodificados de UTF-8 para o texto original.`
    );

    $("plainText").textContent = message;
    $("plainResult").classList.remove("hidden");

  } catch (error) {
    $("decryptError").textContent =
      "Falha na descriptografia. Verifique a chave e o pacote: a senha pode estar incorreta ou os dados podem ter sido alterados.";

    showStep(
      3,
      "Validação não concluída: chave incorreta ou pacote alterado."
    );

  } finally {
    button.disabled = false;
    button.textContent = "Descriptografar ↙";
  }
});

// COPIAR PACOTE CRIPTOGRAFADO
$("copyBtn").addEventListener("click", async () => {
  const value = $("ciphertext").value;

  if (!value) {
    $("decryptError").textContent =
      "Não há pacote para copiar.";
    return;
  }

  try {
    await navigator.clipboard.writeText(value);

    $("copyBtn").textContent = "Copiado ✓";

    setTimeout(() => {
      $("copyBtn").textContent = "Copiar pacote";
    }, 1600);

  } catch {
    $("decryptError").textContent =
      "Não foi possível copiar automaticamente. Selecione e copie o pacote.";
  }
});

// MOSTRAR OU OCULTAR A CHAVE
document.querySelectorAll(".eye").forEach(button => {
  button.addEventListener("click", () => {
    const field = $(button.dataset.target);

    field.type =
      field.type === "password" ? "text" : "password";
  });
});
