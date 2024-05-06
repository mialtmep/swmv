# Simple Web Media Viewer
Предпросмотр локальных медиа файлов в виде веб "галереи". Просмотр самих файлов происходит либо в браузере, либо в заданных мобильных приложения (при их использовании рекомендуется использовать флаг `-query_auth`)

## Возможности
- Условно адаптивный дизайн под десктоп и телефоны;
- Поддержка тёмной и светлой темы;
- Возможность использование кастомного FFmpeg;
- Возможность использование собственных TLS сертификатов;
- Полная работоспособность без JS.

## Установка
```bash
git clone --depth=1 https://github.com/mialtmep/swmv
cd swmv
go build
```

## Пример использования
`swmv -cert %путь до сертификата% -key %путь до приватного ключа% -qr .` — запуск в рабочей директории с шифрованием трафика и использованием заданного сертификата; автоматически распознает доменное имя и будет использовать при генерации QR кода.

## Баги
- Какие-то видео пропускаются при обработке, возможно связано с использованием спецсимволов в имени файла.

## Использованные сторонние ресурсы
### Go модули
- [Echo](https://github.com/labstack/echo) — веб фреймфорк для Go;
- [go-qr](https://github.com/piglig/go-qr/) — модуль генерации QR кодов для Go;
### Прочее
- [Bulma](https://github.com/jgthms/bulma/) — лёгкий CSS фреймворк;
- [JetBrainsMono](https://github.com/JetBrains/JetBrainsMono) — моноширинный шрифт
