import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { secureHeaders } from "hono/secure-headers";
import { env } from "hono/adapter";
import { HTTPException } from "hono/http-exception";
import { ERR_BODY_TOO_LARGE, ERR_GENERIC, ERR_SERVER } from "@/lib/error/static";

/**
 * The main Hono server instance.
 */
const app = new Hono();

/**
 * === MIDDLEWARES ===
 */

app.use(logger());

app.use(secureHeaders());

app.use(cors({
  origin(origin, c) {
    return env(c).CORS_ORIGIN;
  },

  allowMethods: ["GET", "HEAD", "POST"]
}));

app.use(bodyLimit({
  maxSize: 4096, // 4 KiB

  onError(c) {
    return c.json(ERR_BODY_TOO_LARGE, 413);
  }
}));

/**
 * Error handler.
 */
app.onError((error, c) => {
  if (!(error instanceof HTTPException)) {
    console.error(error);
    return c.json(ERR_SERVER, 500);
  }

  const response = error.getResponse();

  if (response.headers.has("Content-Type")) {
    return response;
  }

  return c.json(
    error.message ? { ...ERR_GENERIC, message: error.message } : ERR_GENERIC,
    error.status || 500
  );
});

app.notFound((c) => c.body(null, 404));

app.all("/health", (c) => c.text("OK", 200));

export default app;
