import dotenv from "dotenv";
dotenv.config();

import pg from "pg";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

const connectionString = process.env.DATABASE_URL;

const pool = new pg.Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false,
  },
  max: 5,
  min: 2,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
});

pool.on("error", (err) => {
  console.warn("Recovering from idle client connection error:", err.message);
});

const adapter = new PrismaPg(pool, {
  onPoolError: (err) => console.warn("Prisma PG Pool warning:", err.message),
  onConnectionError: (err) => console.warn("Prisma PG Connection warning:", err.message),
});

const prisma = new PrismaClient({ adapter });

export default prisma;

