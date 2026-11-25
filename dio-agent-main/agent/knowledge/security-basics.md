# Fundamentos de Segurança de Aplicações (AppSec)

Este documento é a base de conhecimento do agente de segurança. Use-o para contextualizar análises, classificar vulnerabilidades e recomendar correções com embasamento técnico.

---

## 1. Conceitos Fundamentais

### Vulnerabilidade
Uma fraqueza ou brecha no software, hardware, processo ou comportamento humano que pode ser explorada por uma ameaça. Vulnerabilidades podem ser:
- **Técnicas:** falhas de código, configuração incorreta, dependências desatualizadas.
- **Lógicas:** falhas no fluxo da aplicação, controles de acesso mal projetados.
- **Humanas:** engenharia social, senhas fracas, falta de treinamento.

### Ameaça
Qualquer fator com potencial de causar dano ou explorar uma vulnerabilidade. Classificadas por origem:
- **Externas:** agentes maliciosos, grupos de ransomware, bots automatizados.
- **Internas:** funcionários mal-intencionados, erros acidentais de equipe.
- **Ambientais:** falhas de infraestrutura, desastres naturais.

### Risco
A probabilidade de uma ameaça explorar uma vulnerabilidade multiplicada pelo impacto gerado:

```
Risco = Probabilidade × Impacto
```

Ao reportar uma vulnerabilidade, sempre classifique o risco em:
| Nível | Critério |
|-------|----------|
| **Crítico** | Exploração imediata, impacto total no sistema |
| **Alto** | Exploração provável, impacto severo |
| **Médio** | Exploração possível, impacto moderado |
| **Baixo** | Exploração improvável ou impacto mínimo |
| **Informativo** | Má prática sem impacto direto imediato |

---

## 2. A Tríade CIA

Toda análise de segurança deve medir o impacto sobre os três pilares fundamentais:

### Confidencialidade
Garantir que a informação só fique acessível a pessoas autorizadas.
- Quebrada por: vazamento de dados, SQL Injection que expõe registros, credenciais expostas em logs.
- Controles: criptografia, controle de acesso, mascaramento de dados sensíveis.

### Integridade
Garantir que a informação permaneça exata, completa e sem alterações não autorizadas.
- Quebrada por: injeção de dados maliciosos, adulteração de tokens, CSRF que executa ações não autorizadas.
- Controles: assinaturas digitais, checksums, validação de entrada, logs imutáveis.

### Disponibilidade
Garantir que sistemas e dados fiquem acessíveis sempre que usuários autorizados precisarem.
- Quebrada por: ataques DDoS, falhas de infraestrutura, ransomware.
- Controles: redundância, rate limiting, backups, planos de continuidade.

---

## 3. OWASP Top 10 — Referência de Vulnerabilidades Web

O OWASP Top 10 é o padrão mais adotado para classificação de vulnerabilidades em aplicações web. Ao identificar uma falha, mapeie-a para a categoria correspondente.

| # | Categoria | Descrição Resumida |
|---|-----------|-------------------|
| A01 | **Broken Access Control** | Usuários acessam recursos ou executam ações além do seu nível de permissão |
| A02 | **Cryptographic Failures** | Dados sensíveis expostos por falha ou ausência de criptografia |
| A03 | **Injection** | Dados não sanitizados executados como código (SQL, OS, LDAP, XSS) |
| A04 | **Insecure Design** | Falhas arquiteturais que não podem ser corrigidas apenas com código |
| A05 | **Security Misconfiguration** | Configurações padrão inseguras, permissões excessivas, headers ausentes |
| A06 | **Vulnerable Components** | Uso de bibliotecas, frameworks ou dependências com vulnerabilidades conhecidas |
| A07 | **Auth Failures** | Falhas em autenticação, gerenciamento de sessão ou recuperação de senha |
| A08 | **Software & Data Integrity** | Desserialização insegura, CI/CD sem validação, atualizações sem verificação |
| A09 | **Logging & Monitoring Failures** | Ausência de logs adequados que permitam detectar e responder a incidentes |
| A10 | **SSRF** | Servidor realiza requisições para destinos controlados pelo atacante |

---

## 4. Vulnerabilidades Mais Comuns — Detalhe Técnico

### SQL Injection (A03)
Ocorre quando input do usuário é concatenado diretamente em queries SQL.

**Padrão vulnerável:**
```python
query = "SELECT * FROM users WHERE username='" + username + "'"
```

**Correção — sempre use parâmetros preparados:**
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

**Impacto:** leitura, alteração ou exclusão de dados; bypass de autenticação; em casos extremos, execução de comandos no servidor.

---

### Cross-Site Scripting — XSS (A03)
Ocorre quando input do usuário é renderizado no HTML sem sanitização, permitindo injeção de scripts.

**Tipos:**
- **Refletido:** o script é injetado na URL e refletido na resposta imediata.
- **Armazenado:** o script é salvo no banco e executado para todos que acessam a página.
- **DOM-based:** a manipulação ocorre no JavaScript do lado do cliente.

**Padrão vulnerável:**
```python
return f"<h1>Olá, {nome}!</h1>"  # nome pode conter <script>
```

**Correção:**
```python
from markupsafe import escape
return f"<h1>Olá, {escape(nome)}!</h1>"
```

**Impacto:** roubo de cookies/sessão, redirecionamento malicioso, keylogging no navegador da vítima.

---

### Broken Access Control (A01)
Ocorre quando a aplicação não verifica corretamente se o usuário tem permissão para acessar um recurso.

**Exemplo — IDOR (Insecure Direct Object Reference):**
```
GET /api/fatura?id=1042   # usuário A vê a fatura de outro usuário
```

**Correção:** sempre verificar se o recurso solicitado pertence ao usuário autenticado antes de retorná-lo.

---

### Security Misconfiguration (A05)
Configurações padrão inseguras ou ausência de headers de segurança HTTP.

**Headers essenciais que devem estar presentes:**
| Header | Função |
|--------|--------|
| `Content-Security-Policy` | Restringe origens de scripts e recursos |
| `X-Content-Type-Options: nosniff` | Impede MIME sniffing |
| `X-Frame-Options: DENY` | Protege contra clickjacking |
| `Strict-Transport-Security` | Força HTTPS |
| `Referrer-Policy` | Controla informações enviadas no cabeçalho Referer |

---

## 5. Boas Práticas de Desenvolvimento Seguro

### Nunca Confie no Input do Usuário
Toda entrada de dados — formulários, URLs, APIs, cookies, headers — deve ser:
1. **Validada:** verificar tipo, formato, tamanho e valores permitidos.
2. **Sanitizada:** remover ou escapar caracteres perigosos antes de usar.
3. **Parametrizada:** nunca concatenar input diretamente em queries ou comandos.

### Princípio do Menor Privilégio
Usuários, serviços e conexões de banco de dados devem ter apenas as permissões estritamente necessárias:
- Conexão de banco de dados da aplicação: somente `SELECT`, `INSERT`, `UPDATE` nas tabelas necessárias. Nunca `DROP` ou `CREATE`.
- Usuários: acesso somente aos recursos da sua função.
- APIs: tokens com escopos mínimos necessários.

### Defesa em Profundidade
Implementar múltiplas camadas de segurança independentes:
```
[ Frontend ] → validação básica de UX
[ Backend  ] → validação e sanitização real
[ Banco    ] → queries parametrizadas + permissões mínimas
[ Rede     ] → HTTPS + firewall + rate limiting
[ Infra    ] → patches atualizados + monitoramento
```
Se uma camada falhar, as outras ainda protegem.

### Fail Securely
Em caso de erro, a aplicação deve falhar de forma segura — sem expor stack traces, dados internos ou mensagens de erro detalhadas ao usuário:
```python
# ❌ Expõe informações internas
except Exception as e:
    return str(e)

# ✅ Mensagem genérica para o usuário, log detalhado interno
except Exception as e:
    logger.error(f"Erro interno: {e}")
    return "Ocorreu um erro. Tente novamente mais tarde."
```

---

## 6. Autenticação e Gerenciamento de Sessão

### Senhas
- Nunca armazene senhas em texto plano ou com MD5/SHA1.
- Use algoritmos de hashing com salt: **bcrypt**, **Argon2** ou **PBKDF2**.
- Exija senhas com no mínimo 12 caracteres, letras, números e símbolos.

### Tokens e Sessões
- Tokens de sessão devem ser longos, aleatórios e invalidados no logout.
- Cookies de sessão devem ter as flags: `HttpOnly`, `Secure`, `SameSite=Strict`.
- Implemente expiração de sessão por inatividade.

### Autenticação Multi-Fator (MFA)
- MFA reduz drasticamente o risco de comprometimento mesmo com senha exposta.
- Priorize TOTP (Google Authenticator) sobre SMS, que é suscetível a SIM swapping.

---

## 7. Criptografia — Conceitos Essenciais

| Conceito | Descrição |
|----------|-----------|
| **Criptografia simétrica** | Mesma chave para criptografar e descriptografar (ex: AES). Rápida, usada para dados em repouso. |
| **Criptografia assimétrica** | Par de chaves pública/privada (ex: RSA, ECC). Usada para troca de chaves e assinaturas digitais. |
| **Hashing** | Função unidirecional — não é possível reverter (ex: SHA-256, bcrypt). Usada para senhas e integridade. |
| **TLS/HTTPS** | Protocolo que combina criptografia assimétrica (handshake) e simétrica (dados) para comunicação segura. |

**Regras de ouro:**
- Nunca implemente seu próprio algoritmo de criptografia.
- Dados sensíveis em repouso: criptografados (AES-256 ou Fernet).
- Dados em trânsito: sempre via HTTPS/TLS 1.2+.
- Chaves nunca hardcoded no código-fonte — use variáveis de ambiente ou cofres de segredos.

---

## 8. Como Estruturar um Relatório de Vulnerabilidade

Ao identificar uma vulnerabilidade, reporte sempre com:

```
1. TÍTULO            → Nome curto e descritivo
2. CLASSIFICAÇÃO     → OWASP Top 10, CWE ou CVE se aplicável
3. SEVERIDADE        → Crítico / Alto / Médio / Baixo / Informativo
4. LOCALIZAÇÃO       → Arquivo, rota, função ou endpoint afetado
5. DESCRIÇÃO         → O que é a falha e por que é perigosa
6. PROVA DE CONCEITO → Como reproduzir (payload, request, etc.)
7. IMPACTO           → O que um atacante pode fazer ao explorar
8. RECOMENDAÇÃO      → Como corrigir, com exemplo de código seguro
```

---

## 9. Referências

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
- [CVE — Common Vulnerabilities and Exposures](https://cve.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
