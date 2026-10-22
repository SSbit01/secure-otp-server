import { Hono } from "hono";
import otpApp from "@/routes/otp";

const routesApp = new Hono();

routesApp.all("/health", (c) => c.text("OK", 200));

routesApp.route("/api/otp", otpApp);

export default routesApp;
