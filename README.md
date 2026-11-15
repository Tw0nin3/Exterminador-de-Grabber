# Discord Grabber Remover

Ferramenta para Windows que procura indícios de injeção em scripts do módulo `discord_desktop_core` do Discord. A análise é local e não envia dados pela rede. Os resultados são indícios, não uma confirmação de malware.

## Executar

Instale Python 3.10 ou superior para Windows com o componente **tcl/tk**. No terminal:

```powershell
git clone https://github.com/Tw0nin3/DiscordGrabberRemover.git
cd DiscordGrabberRemover
py discord_grabber_remover.py
```

Não há bibliotecas externas para instalar. Clique em **Verificar Discord**; se a instalação não for encontrada, escolha a pasta que contém os diretórios `app-*`. Selecione um resultado para conferir os motivos e o SHA-256. O botão de quarentena atua somente sobre o arquivo selecionado, após confirmação. Feche o Discord antes da operação; mover um arquivo essencial pode impedir sua inicialização. A cópia e um arquivo JSON de restauração ficam em `%LOCALAPPDATA%\DiscordGrabberRemover\quarantine`. Use **Restaurar quarentena** e selecione o JSON correspondente. A restauração não sobrescreve arquivos existentes.

Para análise sem interface:

```powershell
py discord_grabber_remover.py --scan
py discord_grabber_remover.py --scan --path "C:\Users\USUARIO\AppData\Local\Discord"
py -m unittest -v
```

O resultado da linha de comando é JSON; código 2 indica que não foram encontradas instalações ou houve avisos de leitura. Um resultado vazio não prova que a instalação está limpa.

## Escopo e limitações

A ferramenta procura combinações e indícios conhecidos em arquivos JavaScript nos diretórios `app-*/modules/discord_desktop_core-*/discord_desktop_core`, incluindo as variantes Stable, Canary, PTB e Development nos caminhos locais padrão. Ela não executa os arquivos inspecionados nem exibe os trechos encontrados, evitando divulgar credenciais. Arquivos maiores que 10 MiB são ignorados e registrados como aviso. Padrões podem produzir falsos positivos e não detectam todas as variantes. Arquivos ASAR, persistência, tarefas agendadas e processos **não são analisados**; a ferramenta não pode garantir a integridade do sistema nem remover outras infecções.

Se houver suspeita de comprometimento, use uma ferramenta antivírus confiável e reinstale o Discord obtido do site oficial. Em outro dispositivo confiável, troque sua senha do Discord, encerre sessões ativas e revise suas configurações de segurança. A quarentena não invalida credenciais já expostas.

Licença: MIT, veja LICENSE.
