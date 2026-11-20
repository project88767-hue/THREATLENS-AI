import { app } from "./app";
import { env } from "./config/env";

app.listen(env.PORT, () => {
  console.log(
    `[THREATLENS-AI] Backend API listening on http://localhost:${env.PORT} (${env.NODE_ENV})`
  );
});
