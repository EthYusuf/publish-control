---
name: publish-control
description: >-
  Use this skill whenever the user asks for "/publish-control", pre-publish code review, security audit,
  or wants to verify project code safety before deployment.
---

# Publish Control Security Gate

Bu beceri, projenin yayına alınmadan önce 17 farklı güvenlik kategorisinde derinlemesine taranmasını sağlar.

## Çalıştırma Adımları

1. `publish_control` tool'unu projenin mutlak kök dizini ile çağırın:
   - `projectPath`: Taranacak projenin kök dizini (ör. çalışma dizini)
   - `severity`: "all" (veya "high")

2. Dönen Markdown raporunu kullanıcıya sunun.

3. Kullanıcı belirli bir bulguyu düzeltmek isterse `publish_control_fix` aracını bulgu ID'si (ör. `SEC-001`, `INJ-002`) ile çağırarak düzeltme önerisi alın.
