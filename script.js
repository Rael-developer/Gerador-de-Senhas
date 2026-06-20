const CHAR_SETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// Mapeamento do DOM
const lengthSlider = document.getElementById('length-slider');
const lengthVal = document.getElementById('length-val');
const generatedPassInput = document.getElementById('generated-password');
const generateBtn = document.getElementById('generate-btn');
const copyBtn = document.getElementById('copy-btn');
const passwordInput = document.getElementById('password-input');
const strengthBar = document.getElementById('strength-bar');
const strengthLabel = document.getElementById('strength-label');
const leakStatus = document.getElementById('leak-status');

const reqs = {
    length: document.getElementById('req-length'),
    upper: document.getElementById('req-upper'),
    lower: document.getElementById('req-lower'),
    number: document.getElementById('req-number'),
    symbol: document.getElementById('req-symbol')
};

// Variável de controle do Debounce
let debounceTimer;

lengthSlider.addEventListener('input', (e) => {
    lengthVal.textContent = e.target.value;
});

// --- LÓGICA DO GERADOR ---
function generateSecurePassword() {
    const length = parseInt(lengthSlider.value);
    let allowedChars = '';
    let password = [];

    if (document.getElementById('chk-uppercase').checked) {
        allowedChars += CHAR_SETS.uppercase;
        password.push(CHAR_SETS.uppercase[getRandomIndex(CHAR_SETS.uppercase.length)]);
    }
    if (document.getElementById('chk-lowercase').checked) {
        allowedChars += CHAR_SETS.lowercase;
        password.push(CHAR_SETS.lowercase[getRandomIndex(CHAR_SETS.lowercase.length)]);
    }
    if (document.getElementById('chk-numbers').checked) {
        allowedChars += CHAR_SETS.numbers;
        password.push(CHAR_SETS.numbers[getRandomIndex(CHAR_SETS.numbers.length)]);
    }
    if (document.getElementById('chk-symbols').checked) {
        allowedChars += CHAR_SETS.symbols;
        password.push(CHAR_SETS.symbols[getRandomIndex(CHAR_SETS.symbols.length)]);
    }

    if (allowedChars === '') {
        allowedChars = CHAR_SETS.lowercase;
        password.push(CHAR_SETS.lowercase[getRandomIndex(CHAR_SETS.lowercase.length)]);
    }

    while (password.length < length) {
        const randomIndex = getRandomIndex(allowedChars.length);
        password.push(allowedChars[randomIndex]);
    }

    for (let i = password.length - 1; i > 0; i--) {
        const j = getRandomIndex(i + 1);
        [password[i], password[j]] = [password[j], password[i]];
    }

    generatedPassInput.value = password.join('');
}

function getRandomIndex(max) {
    const randomBuffer = new Uint32Array(1);
    window.crypto.getRandomValues(randomBuffer);
    return randomBuffer[0] % max;
}

// --- LÓGICA DO VERIFICADOR & ENTROPIA ---
function checkPasswordStrength(password) {
    let score = 0;

    const checks = {
        length: password.length >= 12,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password)
    };

    toggleRequirementUI(reqs.length, checks.length);
    toggleRequirementUI(reqs.upper, checks.upper);
    toggleRequirementUI(reqs.lower, checks.lower);
    toggleRequirementUI(reqs.number, checks.number);
    toggleRequirementUI(reqs.symbol, checks.symbol);

    if (password === "") {
        updateProgressBar(0, 'Inexistente', 'transparent');
        leakStatus.style.display = 'none';
        return;
    }

    if (checks.length) score++;
    if (checks.upper) score++;
    if (checks.lower) score++;
    if (checks.number) score++;
    if (checks.symbol) score++;

    if (score <= 2) {
        updateProgressBar(33, 'FRACA (Risco Crítico)', '#ff3131');
    } else if (score <= 4) {
        updateProgressBar(66, 'MÉDIA (Vulnerável)', '#ffdf00');
    } else if (score === 5) {
        updateProgressBar(100, 'FORTE (Excelente)', '#39ff14');
    }
}

function toggleRequirementUI(element, isValid) {
    if (isValid) {
        element.classList.remove('invalid');
        element.classList.add('valid');
    } else {
        element.classList.remove('valid');
        element.classList.add('invalid');
    }
}

function updateProgressBar(width, text, color) {
    strengthBar.style.width = `${width}%`;
    strengthBar.style.backgroundColor = color;
    strengthLabel.textContent = text;
    strengthLabel.style.color = color;
}

// --- SEGURANÇA AVANÇADA: VERIFICAÇÃO DE VAZAMENTO (K-ANONYMITY) ---

// Auxiliar para gerar o hash SHA-1 nativamente no navegador
async function sha1(string) {
    const buffer = new TextEncoder().encode(string);
    const hashBuffer = await window.crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Função Assíncrona para consultar o HIBP com preservação de privacidade
async function checkLeakAPI(password) {
    if (!password) return;

    leakStatus.className = "leak-status checking";
    leakStatus.textContent = "🔍 Varrendo bancos de dados criminosos em busca de correspondências...";

    try {
        const hash = await sha1(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        // Requisição enviando APENAS os 5 primeiros caracteres (K-Anônimato)
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        
        if (!response.ok) throw new Error("Erro ao consultar a base de vazamentos.");

        const text = await response.text();
        const lines = text.split('\n');
        
        let leakCount = 0;

        // Varre a resposta buscando se o sufixo da nossa senha está na lista
        for (let line of lines) {
            const [returnedSuffix, count] = line.split(':');
            if (returnedSuffix.trim() === suffix) {
                leakCount = parseInt(count);
                break;
            }
        }

        // Renderiza o resultado na UI baseado no retorno
        if (leakCount > 0) {
            leakStatus.className = "leak-status compromised";
            leakStatus.textContent = `⚠️ Alerta de Segurança: Esta senha já vazou ${leakCount.toLocaleString()} vezes na internet e não deve ser utilizada!`;
        } else {
            leakStatus.className = "leak-status safe";
            leakStatus.textContent = "✅ Senha Protegida: Esta senha nunca foi encontrada em vazamentos na internet.";
        }

    } catch (error) {
        leakStatus.className = "leak-status checking";
        leakStatus.textContent = "⚠️ Não foi possível validar os vazamentos no momento (Offline).";
        console.error(error);
    }
}

// --- LISTENERS COM IMPLEMENTAÇÃO DE DEBOUNCE ---

passwordInput.addEventListener('input', (e) => {
    const password = e.target.value;
    
    // Análise de entropia local permanece instantânea para melhor UX
    checkPasswordStrength(password);

    // Limpa o timer anterior do debounce para reiniciar a contagem
    clearTimeout(debounceTimer);

    // Configura a requisição da API para disparar apenas após 500ms de inatividade do teclado
    if (password !== "") {
        debounceTimer = setTimeout(() => {
            checkLeakAPI(password);
        }, 500);
    }
});

generateBtn.addEventListener('click', () => {
    generateSecurePassword();
    // Limpa a análise de vazamento da aba de testes ao gerar uma nova senha aleatória
    passwordInput.value = "";
    checkPasswordStrength("");
});

copyBtn.addEventListener('click', () => {
    if (!generatedPassInput.value) return;
    navigator.clipboard.writeText(generatedPassInput.value);
    const originalText = copyBtn.textContent;
    copyBtn.textContent = 'Copiado!';
    copyBtn.style.borderColor = '#39ff14';
    copyBtn.style.color = '#39ff14';
    
    setTimeout(() => {
        copyBtn.textContent = originalText;
        copyBtn.style.borderColor = '';
        copyBtn.style.color = '';
    }, 2000);
});

// Inicialização
generateSecurePassword();

