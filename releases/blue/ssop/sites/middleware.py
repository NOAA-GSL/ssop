import logging
logger = logging.getLogger('ssop.models')

class SsopMiddleware:
    def __init__(self, get_response):
        msg = "    __init__ pre get_response is: " + str(get_response)
        logger.info(msg)
        self.get_response = get_response
        msg = "    __init__ post get_response is: " + str(get_response)
        logger.info(msg)

    def __call__(self, request):
        msg = "    __call__ pre request is: " + str(request)
        logger.info(msg)
        response = self.get_response(request)
        msg = "    __call__ post request is: " + str(request)
        logger.info(msg)
        response.headers['ssop-Header'] = msg
        return response

