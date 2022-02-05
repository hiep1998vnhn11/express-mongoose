import { cleanEnv, port, str, num } from 'envalid'

function validateEnv() {
  cleanEnv(process.env, {
    JWT_SECRET: str(),
    JWT_TTL: num(),
    MONGO_PASSWORD: str(),
    MONGO_PATH: str(),
    MONGO_USER: str(),
    PORT: port(),
  })
}

export default validateEnv
