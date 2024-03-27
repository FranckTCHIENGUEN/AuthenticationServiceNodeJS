import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

export const SALT_ROUND = 10;

export const UserModel = prisma.user