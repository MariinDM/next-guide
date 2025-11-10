import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import z from 'zod';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';
import { User } from './app/lib/definitions';
import { email } from 'zod/v4';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User[]>`SELECT * FROM users WHERE email = ${email} LIMIT 1`;
        console.log('User fetched from DB:', user?.[0]?.email || 'not found');
        return user[0];
    } catch (error) {
        console.error('Error fetching user:', error);
        throw new Error('Failed to fetch user');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials) {

            const parsedCredentials = z
                .object({
                    email: z.string().email(),
                    password: z.string().min(6),
                })
                .safeParse(credentials);

            if (!parsedCredentials.success) {
                console.log('❌ Validation failed:', parsedCredentials.error.flatten());
                return null;
            }

            const { email, password } = parsedCredentials.data;

            const user = await getUser(email);
            if (!user) {
                console.log('❌ User not found in database:', email);
                return null;
            }

            const passwordsMatch = await bcrypt.compare(password, user.password);

            if (passwordsMatch) {
                return user;
            }

            return null;
        },
    }),
    ],
});