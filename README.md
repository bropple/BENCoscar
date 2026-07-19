# BENCoscar

> **This is a fork.** BENCoscar is a fork of
> [mk6i/open-oscar-server](https://github.com/mk6i/open-oscar-server), forked at
> tag `v0.24.0`. Nearly all of this code — and all of the documentation below —
> is mk6i's work, used under the MIT licence. Enormous credit to them; if what
> you want is an OSCAR server, **use the upstream project, not this one.**
>
> BENCoscar exists to serve [BENCchat](https://github.com/bropple/BENCchat), a
> self-hosted end-to-end-encrypted messenger that uses OSCAR as its transport.
> Changes here serve that goal, not classic AIM/ICQ compatibility.
> **Bug reports about OSCAR server behaviour belong upstream**, where they reach
> the person who actually wrote it.
>
> The BENCO delta over upstream is always exactly
> `git log --oneline upstream/main..benco`. See [`CLAUDE.md`](CLAUDE.md) for fork
> policy and [`AGENTS.md`](AGENTS.md) for upstream's architecture guide.
>
> Badges and links below point at the **upstream** project.

---

<div align="center">

<a href="">[![codecov](https://codecov.io/gh/mk6i/open-oscar-server/graph/badge.svg?token=MATKPP77JT)](https://codecov.io/gh/mk6i/open-oscar-server)</a>
<a href="">[![Discord](https://img.shields.io/discord/1238648671348719626?logo=discord&logoColor=white)](https://discord.gg/2Xy4nF3Uh9)</a>

</div>

**Open OSCAR Server** is an open-source instant messaging server compatible with classic AIM and ICQ clients written in golang.

<p align="center">
<img width="816" alt="image" src="https://github.com/user-attachments/assets/4d76b06f-fd0c-4f0a-9e9f-d9516653cfb4" /><br/>
<i>Above: <a href="https://www.pidgin.im/">Pidgin</a> IM connected to Open OSCAR Server</i>
</p>

| Disclaimer                                                                                                                                                                                                                           |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| This project is an independent, open-source initiative and is not affiliated with, endorsed by, or associated with AOL or Yahoo! Inc. This project is entirely non-commercial and does not generate any revenue or accept donations. |

The following features are supported:

**AIM**

- [x] Windows AIM Clients: [v1.x-v5.x](./docs/CLIENT.md), [v6.x-v7.x](docs/AIM_6_7.md)
- [x] Away Messages
- [x] Buddy Icons (v4.x, v5.x)
- [x] Buddy List
- [x] Chat Rooms
- [x] Public & Private Chat Exchanges
- [x] Instant Messaging
- [x] User Profiles
- [x] Privacy (allow or block specific users)
- [x] Warning
- [x] User Directory Search
- [x] TOC1 Protocol Clients: Quick Buddy, gaim, [TiK](./docs/CLIENT_TIK.md)
- [x] TOC2 Protocol Clients: [vAIM](https://www.onlyup.net/vaim/index.html), Miranda ~v0.4.0.3, iEM 1.0.1
- [x] File Sharing
    - LAN Only: Direct Connect, Get File
    - Lan/Internet: [Send File](./docs/RENDEZVOUS.md)

**ICQ**

- [x] Windows ICQ Clients: [98x, 99x, 2000x, 2001x, 2002x, 2003x, 4, 5](./docs/CLIENT_ICQ.md)
- [x] Instant Messaging
- [x] Profiles
- [x] User Search
- [x] Presence Statuses
- [x] Offline Messaging

## 🏁 How to Run

Get up and running with Open OSCAR Server using one of these handy server quickstart guides:

* [Linux (x86_64)](./docs/LINUX.md)
* [macOS (Intel and Apple Silicon)](./docs/MACOS.md)
* [Windows 10/11 (x86_64)](./docs/WINDOWS.md)

Don't have AIM installed yet? Check out the [AIM Client Setup Guide](./docs/CLIENT.md).

...how about ICQ? Check out the [ICQ Client Setup Guide](./docs/CLIENT_ICQ.md).

## 🛠️ Development

This project is under active development. Contributions are welcome!

Follow [this guide](./docs/BUILD.md) to learn how to compile and run Open OSCAR Server.

## 🌍 Community

Check out the Open OSCAR Server [Discord server](https://discord.gg/zjFGGTa8mu) to get help or find out how to get
involved.

### Tooling Provided By

[![JetBrains logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg)](https://jb.gg/OpenSource)

## 👤 Management API

The Management API provides functionality for administering the server (see [OpenAPI spec](./api.yml)). The following
shows you how to run these commands via the command line.

### Windows PowerShell

> Run these commands from **PowerShell**, *not* **Command Prompt**.

#### List Users

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user -Method Get
```

#### Create Users

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user `
  -Body '{"screen_name":"MyScreenName", "password":"thepassword"}' `
  -Method Post `
  -ContentType "application/json"
```

#### Delete Users

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user `
  -Body '{"screen_name": "user123"}' `
  -Method Delete `
  -ContentType "application/json"
```

#### Change Password

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user/password `
  -Body '{"screen_name":"MyScreenName", "password":"thenewpassword"}' `
  -Method Put `
  -ContentType "application/json"
```

#### List Active Sessions

This request lists sessions for all logged in users.

```powershell
Invoke-WebRequest -Uri http://localhost:8080/session -Method Get
```

#### Create Public Chat Room

```powershell
Invoke-WebRequest -Uri http://localhost:8080/chat/room/public `
  -Body '{"name":"Office Hijinks"}' `
  -Method Post `
  -ContentType "application/json"
```

#### List Public Chat Rooms

```powershell
Invoke-WebRequest -Uri http://localhost:8080/chat/room/public -Method Get
```

### macOS / Linux / FreeBSD

#### List Users

```shell
curl http://localhost:8080/user
```

#### Create Users

##### AIM

```shell
curl -d'{"screen_name":"MyScreenName", "password":"thepassword"}' http://localhost:8080/user
```

##### ICQ

```shell
curl -d'{"screen_name":"100003", "password":"thepassw"}' http://localhost:8080/user
```

#### Delete Users

```shell
curl -X DELETE -d '{"screen_name": "user123"}' http://localhost:8080/user
```

#### Change Password

```shell
curl -X PUT -d'{"screen_name":"MyScreenName", "password":"thenewpassword"}' http://localhost:8080/user/password
```

#### List Active Sessions

This request lists sessions for all logged in users.

```shell
curl http://localhost:8080/session
```

#### Create Public Chat Room

```shell
curl -d'{"name":"Office Hijinks"}' http://localhost:8080/chat/room/public
```

#### List Public Chat Rooms

```shell
curl http://localhost:8080/chat/room/public
```

## 📄 License

Open OSCAR Server is licensed under the [MIT license](./LICENSE).
