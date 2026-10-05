"""Bound all request bodies, including multipart/chunked uploads before spooling."""
from starlette.formparsers import MultiPartException


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST':
            return await self.app(scope, receive, send)
        consumed, exceeded = 0, False

        async def bounded_receive():
            nonlocal consumed, exceeded
            message = await receive()
            if message['type'] == 'http.request':
                consumed += len(message.get('body', b''))
                if consumed > self.max_bytes:
                    exceeded = True
                    # Starlette closes already-spooled files on MultiPartException.
                    raise MultiPartException('Upload exceeds the 25 MB capture limit (including multipart overhead).')
            return message

        async def bounded_send(message):
            if exceeded and message['type'] == 'http.response.start':
                message = dict(message, status=413)
            await send(message)

        return await self.app(scope, bounded_receive, bounded_send)
