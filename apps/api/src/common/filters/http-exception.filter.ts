import { ArgumentsHost, Catch, HttpException, HttpStatus, type ExceptionFilter } from "@nestjs/common";
import { createLogger } from "@dsrclone/logger";

const logger = createLogger("dsrclone-api");

/** Central error handling: production responses never leak stack traces,
 *  database details, filesystem paths or internal commands. */
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<{ status: (n: number) => { json: (b: unknown) => void } }>();
    const req = ctx.getRequest<{ requestId?: string; url?: string }>();
    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | string[] = "Internal server error";
    let issues: unknown;
    if (exception instanceof HttpException) {
      const body = exception.getResponse() as { message?: string | string[]; issues?: unknown };
      message = body.message ?? exception.message;
      issues = body.issues;
    } else {
      logger.error("unhandled exception", { error: exception instanceof Error ? exception.message : "unknown", url: req.url });
    }
    res.status(status).json({
      statusCode: status,
      message,
      ...(issues ? { issues } : {}),
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
    });
  }
}
