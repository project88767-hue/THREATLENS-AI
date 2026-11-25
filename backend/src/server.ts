import { app } from "./app";
import { env } from "./config/env";
import { bootstrapAdmin } from "./bootstrapAdmin";

const host = process.env.HOST || "0.0.0.0";

app.listen(env.PORT, host, () => {
  console.log(
    `[THREATLENS-AI] Platform listening on http://${host}:${env.PORT} (${env.NODE_ENV})`
  );
  void bootstrapAdmin();
});
