# Отчет по практическому заданию «Основы безопасности инфраструктуры»

В данном отчете проанализированы уязвимости в исходном Ansible-playbook и описаны внесенные исправления для повышения безопасности инфраструктуры:

1. [Устранены жестко закодированные секреты](#1-жестко-заданные-секреты-hard-coded-secrets)
2. [Настроен брандмауэр для ограничения доступа](#2-отключение-брандмауэра)
3. [Добавлена проверка целостности загружаемых файлов](#3-отсутствие-проверки-контрольной-суммы)
4. [Обновлен Docker-образ до более свежей версии](#4-использование-устаревшего-docker-образа)
5. [Установлены правильные разрешения на файлы и директории](#5-небезопасные-права-доступа-на-директорию)
6. [Реализовано безопасное хранение и управление токенами](#6-небезопасное-хранение-токена-в-html)
7. [Добавлены другие улучшения безопасности контейнера](#7-дополнительные-улучшения-безопасности-контейнера)
8. [Ограничены привилегии sudo для пользователя приложения](#8-ограничение-прав-sudo)

## Обнаруженные уязвимости и их устранение

### 1. Жестко заданные секреты (hard-coded secrets)

**Проблема:** В исходном playbook пароль был указан прямо в коде:
```yaml
vars:
  app_password: "Sup3rS3cr3tP@ssw0rd123"
```

**Почему это опасно:** 
- Храненить пароли в открытом виде плохо где угодно: хоть в базе данных, хоть в плейбуке, потому что при компрометации репозитория эти пароли утекут
- Такие пароли часто не меняются и могут попасть в историю коммитов
- Все, имеющие доступ к коду, получают доступ к секретам

**Исправление:**
```yaml
vars_prompt:
  - name: app_password
    prompt: "Enter password for app user"
    private: yes
```

Теперь пароль запрашивается интерактивно при выполнении playbook и не хранится в исходном коде.

### 2. Отключение брандмауэра

**Проблема:**
```yaml
- name: Disable firewall to allow all traffic
  shell: ufw disable
  ignore_errors: yes
  tags: network
```

**Риски:**
- Полное отключение брандмауэра открывает все порты системы для атак
- Игнорировать ошибки, о которых сам же компьютер говорит, в принипе плохо, а директива `ignore_errors: yes` означает, что playbook продолжит работу, маскируя потенциальные проблемы
- Меньше контроля над сетевым доступом -> больше поверхность атаки

**Исправление:**
```yaml
- name: Configure firewall to allow only necessary ports
  ufw:
    rule: allow
    port: "8080"
    proto: tcp
  tags: network

- name: Enable firewall
  ufw:
    state: enabled
    policy: deny
  tags: network
```

Вместо отключения брандмауэра настраиваем его для разрешения только необходимого трафика на порту 8080 и запрещаем весь остальной трафик.

### 3. Отсутствие проверки контрольной суммы

**Проблема:**
```yaml
- name: Download application archive
  get_url:
    url: "{{ download_url }}"
    dest: "/tmp/app.tar.gz"
  tags: download
```

**Риски:**
- Без проверки контрольной суммы невозможно убедиться в целостности загружаемого файла
- Злоумышленник может подменить файл при передаче (MitM-attack) и произойдет установка вредоносного ПО вместо оригинального приложения

**Исправление:**
```yaml
- name: Download application archive
  get_url:
    url: "{{ download_url }}"
    dest: "/tmp/app.tar.gz"
    checksum: "{{ download_checksum }}"
    mode: "0640"
    owner: "{{ app_user }}"
  tags: download
```

Добавлена проверка контрольной суммы SHA256, что гарантирует целостность и подлинность загружаемого файла. Также установлены конкретные права доступа.

### 4. Использование устаревшего Docker-образа

**Проблема:**
```yaml
image_version: "1.18.0"
```

**Риски:**
- Устаревшие версии содержат известные уязвимости, которые могут быть использованы для атаки
- Неполная поддержка современных функций безопасности

**Исправление:**
```yaml
image_version: "stable-alpine"
```

Использование тега `stable-alpine` обеспечивает:
1. Автоматическое получение обновлений в рамках стабильной версии
2. Меньший размер образа благодаря использованию Alpine Linux
3. Уменьшение поверхности атаки за счет минимизации компонентов в образе

Дальнейшие улучшения:
- Говорили о том, чтобы завести как бы буфер для всех внешних зависимостей, чтобы можно было проверить обновление в тестовой среде перед его применением в продакшене

### 5. Небезопасные права доступа на директорию

**Проблема:**
```yaml
- name: Set permissions on work directory
  file:
    path: "{{ work_dir }}"
    state: directory
    recurse: yes
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    mode: '0777'
  tags: permissions
```

**Риски:**
- Права `0777` (rwxrwxrwx) разрешают всем пользователям чтение, запись и выполнение
- Любой пользователь в системе может изменить файлы приложения
- Возможно внедрение вредоносного кода через модификацию файлов

**Исправление:**
```yaml
- name: Set appropriate permissions on work directory
  file:
    path: "{{ work_dir }}"
    state: directory
    recurse: yes
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    mode: '0755'
  tags: permissions
```

Установлены более ограничительные права `0755` (rwxr-xr-x), которые позволяют:
- Владельцу (app_user) полный доступ
- Остальным пользователям только чтение и выполнение

### 6. Небезопасное хранение токена в HTML

**Проблема:**
```yaml
- name: Deploy index.html with embedded token
  copy:
    dest: "{{ work_dir }}/index.html"
    content: |
      <!DOCTYPE html>
      <html>
      <head><title>Vulnerable Web App</title></head>
      <body>
        <h1>Welcome</h1>
        <p>Your secret token: {{ secret_token.stdout }}</p>
      </body>
      </html>
```

**Риски:**
- Токен встроен непосредственно в HTML и доступен любому, кто имеет доступ к странице
- Токен кэшируется браузерами и может сохраняться в истории
- Токен отправляется всем посетителям без проверки авторизации

**Исправление:**
```yaml
- name: Create token directory
  file:
    path: "/etc/secure-app"
    state: directory
    owner: root
    group: root
    mode: '0700'
  tags: token

- name: Generate secret token
  shell: openssl rand -hex 16
  register: secret_token
  changed_when: false
  tags: token

- name: Store token in secure file
  copy:
    dest: "{{ token_file }}"
    content: "{{ secret_token.stdout }}"
    owner: root
    group: root
    mode: '0400'
  tags: token

- name: Deploy index.html with reference to token service
  copy:
    dest: "{{ work_dir }}/index.html"
    content: |
      <!DOCTYPE html>
      <html>
      <head><title>Secure Web App</title></head>
      <body>
        <h1>Welcome</h1>
        <p>This is a secure application. Tokens are managed by a separate service.</p>
      </body>
      </html>
```

В исправленной версии:
1. Создается отдельный защищенный каталог для хранения токена
2. Токен сохраняется в файле с очень ограниченными правами (только чтение владельцем)
3. HTML-страница не содержит токен, вместо этого ссылается на отдельный сервис
4. Файл с токеном монтируется в контейнер в режиме "только чтение"

### 7. Дополнительные улучшения безопасности контейнера

В исправленной версии также добавлены важные механизмы безопасности контейнера:

```yaml
- name: Run secure Nginx container
  docker_container:
    name: "{{ container_name }}"
    image: "nginx:{{ image_version }}"
    state: started
    restart_policy: always
    ports:
      - "8080:80"
    volumes:
      - "{{ work_dir }}:/usr/share/nginx/html:ro"
      - "{{ token_file }}:/etc/secrets/token.txt:ro"
    tmpfs:
      - "/var/cache/nginx"
      - "/var/run"
      - "/tmp"
    read_only: true
    security_opts:
      - no-new-privileges:true
    cap_drop:
      - ALL
    capabilities:
      - NET_BIND_SERVICE
      - DAC_OVERRIDE
      - CHOWN
      - SETGID
      - SETUID
```

**Улучшения:**
1. `read_only: true` - файловая система контейнера доступна только для чтения
2. `tmpfs` для временных каталогов - данные не сохраняются после перезапуска
3. `no-new-privileges` - процессы не могут получить дополнительные привилегии
4. `cap_drop: ALL` - удаление всех возможных привилегий Linux
5. Выборочное добавление только необходимых capabilities (без них nginx не запускался)
6. Монтирование всех томов в режиме "только чтение" (:ro)

### 8. Ограничение прав sudo

**Проблема:**
```yaml
- name: Grant passwordless sudo to app user
  copy:
    dest: "/etc/sudoers.d/{{ app_user }}"
    content: "{{ app_user }} ALL=(ALL) NOPASSWD:ALL"
    mode: '0440'
```

**Риски:**
- Пользователь получает полный доступ ко всем командам с правами root
- В случае компрометации этой учетной записи , злоумышленник получает полный контроль над инфраструктурой

**Исправление:**
```yaml
- name: Grant limited sudo access to app user
  copy:
    dest: "/etc/sudoers.d/{{ app_user }}"
    content: "{{ app_user }} ALL=(ALL) NOPASSWD:/usr/bin/docker ps, /usr/bin/systemctl restart nginx"
    mode: '0440'
    validate: "visudo -cf %s"
  tags: sudoers
```

Доступ sudo ограничен только необходимыми командами, и добавлена проверка валидности файла sudoers с помощью `validate`.