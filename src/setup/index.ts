import { Hono } from "hono"

import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { logger } from "hono/logger"
import { secureHeaders } from "hono/secure-headers"

import { env } from "hono/adapter"
import { HTTPException } from "hono/http-exception"

import { ERR_BODY_TOO_LARGE, ERR_SERVER } from "@/lib/error/static"



/**
 * The main Hono server instance.
 */
const app = new Hono()



/**
 * === MIDDLEWARES ===
 */

app.use(logger())


app.use(secureHeaders())


app.use(cors({

  origin(origin, c) {
    return env(c).ORIGIN || "*"
  },

  allowMethods: ["GET", "HEAD", "POST"],

}))


app.use(bodyLimit({

  maxSize: 102400,  // 100 KiB

  onError(c) {
    return c.json(ERR_BODY_TOO_LARGE, 413)
  }

}))



/**
 * Error handler.
 */
app.onError(async(error, c) => {
  
  if (error instanceof HTTPException) {
    return error.getResponse()
  }

  return c.json(ERR_SERVER, 500)

})



app.notFound(c => c.body(null, 404))



export default app