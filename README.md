# sha256-intrinsics

реализация SHA256 на интринсиках, также фоллбэк на чисто процессорные вычисления если интринсики не поддерживаются.

пример
```
struct SHA256 context;
unsigned char digest[32];

sha256_init(&context);

sha256_update(&context, "", 0);

sha256_complete(digest, &context);
/* digest = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
```
