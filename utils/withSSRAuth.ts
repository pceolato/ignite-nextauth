import { GetServerSideProps, GetServerSidePropsContext, GetServerSidePropsResult } from "next"
import { destroyCookie, parseCookies } from "nookies"
import { AuthTokenError } from "../errors/AuthTokenError"
import decode from 'jwt-decode'
import { validadeUserPermissions } from "./validadeUserPermissions"

type withSSRAuthOptions = {
    permissions?: string[];
    roles?: string[];
}

export function withSSRAuth<P>(fn: GetServerSideProps<P>, options?: withSSRAuthOptions): GetServerSideProps {
    return async (ctx: GetServerSidePropsContext): Promise<GetServerSidePropsResult<P>> => {
        const cookies = parseCookies(ctx)
        const token = cookies['nextauth.token']

        if (!cookies['nextauth.token']) {
            return {
                redirect: {
                    destination: '/',
                    permanent: false,
                }
            }
        }

        if (options) {
            const user = decode<{ permissions: string[], roles: string[] }>(token)
            const { permissions, roles } = options

            const userHasValidPermissions = validadeUserPermissions({
                user,
                permissions,
                roles
            })

            if(!userHasValidPermissions) {
                return {
                    redirect: {
                        destination: '/dashboard',
                        permanent: false
                    }
                }
            }
        }

        try {
            return await fn(ctx)
        } catch (error) {
            if (error instanceof AuthTokenError) {
                destroyCookie(ctx, 'nextauth.token')
                destroyCookie(ctx, 'nextauth.refreshToken')

                return {
                    redirect: {
                        destination: '/',
                        permanent: false
                    }
                }
            }

            return {
                redirect: {
                    destination: '/error', // Em caso de um erro não esperado, você pode redirecionar para uma página publica de erro genérico
                    permanent: false
                }
            }
        }
    }
}