import * as bcrypt from 'bcrypt'
import { Request, Response, NextFunction, Router } from 'express'
import * as jwt from 'jsonwebtoken'
import WrongCredentialsException from '../exceptions/WrongCredentialsException'
import Controller from '../interfaces/controller.interface'
import DataStoredInToken from '../interfaces/dataStoredInToken'
import TokenData from '../interfaces/tokenData.interface'
import validationMiddleware from '../middleware/validation.middleware'
import CreateUserDto from '../user/user.dto'
import User from '../user/user.interface'
import userModel from './../user/user.model'
import AuthenticationService from './authentication.service'
import LogInDto from './logIn.dto'
import authMiddleware from '../middleware/auth.middleware'

class AuthenticationController implements Controller {
  public path = '/auth'
  public router = Router()
  public authenticationService = new AuthenticationService()
  private user = userModel

  constructor() {
    this.initializeRoutes()
  }

  private initializeRoutes() {
    this.router.post(
      `${this.path}/register`,
      validationMiddleware(CreateUserDto),
      this.registration
    )
    this.router.post(
      `${this.path}/login`,
      validationMiddleware(LogInDto),
      this.loggingIn
    )
    this.router.get(`${this.path}/me`, authMiddleware, this.getMe)
    this.router.post(`${this.path}/logout`, this.loggingOut)
  }

  private getMe = (request: any, response: Response) => {
    const user: User = request.user
    response.send(user)
  }

  private registration = async (
    request: Request,
    response: Response,
    next: NextFunction
  ) => {
    const userData: CreateUserDto = request.body
    try {
      const { cookie, user } = await this.authenticationService.register(
        userData
      )
      response.setHeader('Set-Cookie', [cookie])
      response.send(user)
    } catch (error) {
      next(error)
    }
  }

  private loggingIn = async (
    request: Request,
    response: Response,
    next: NextFunction
  ) => {
    const logInData: LogInDto = request.body
    const user = await this.user.findOne({ email: logInData.email })
    if (user) {
      const isPasswordMatching = await bcrypt.compare(
        logInData.password,
        user.get('password', null, { getters: false })
      )
      if (isPasswordMatching) {
        const tokenData = this.createToken(user)
        response.send(tokenData)
      } else {
        next(new WrongCredentialsException())
      }
    } else {
      next(new WrongCredentialsException())
    }
  }

  private loggingOut = (request: Request, response: Response) => {
    response.send(200)
  }

  private createToken(user: User): TokenData {
    const { JWT_TTL } = process.env
    const expire_at = 60 * 60 * Number(JWT_TTL)
    const secret = process.env.JWT_SECRET
    const dataStoredInToken: DataStoredInToken = {
      _id: user._id,
    }
    return {
      expire_at,
      access_token: jwt.sign(dataStoredInToken, secret, {
        expiresIn: expire_at,
      }),
    }
  }
}

export default AuthenticationController
