# LMS – Checklist de Conformidade (LGPD / ISO / Acessibilidade)

## Implementado neste pacote
- [x] Endpoints LGPD: exportação de dados, solicitação de exclusão
- [x] Registro de consentimento para analytics
- [x] Banner de cookies com opções
- [x] Cabeçalhos de segurança (CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy)
- [x] Modelos de auditoria e retenção de dados
- [x] Página de Política de Privacidade (placeholder)

## Próximos passos sugeridos
- [ ] Preencher Política de Privacidade oficial + contatos do Encarregado (DPO)
- [ ] Ligar os logs de auditoria onde faz sentido (login, emissão de certificados, etc.)
- [ ] Definir tabela de retenção (DataRetentionPolicy) e job de rotina
- [ ] Adicionar MFA/2FA para administradores
- [ ] Testes de acessibilidade (WCAG 2.1 AA) e legendas de vídeo
