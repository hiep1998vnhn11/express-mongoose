import * as bcrypt from 'bcrypt'
import * as jwt from 'jsonwebtoken'
import UserWithThatEmailAlreadyExistsException from '../exceptions/UserWithThatEmailAlreadyExistsException'
import DataStoredInToken from '../interfaces/dataStoredInToken'
import TokenData from '../interfaces/tokenData.interface'
import CreateUserDto from '../user/user.dto'
import User from '../user/user.interface'
import userModel from './../user/user.model'

class AuthenticationService {
  public user = userModel

  public async register(userData: CreateUserDto) {
    if (await this.user.findOne({ email: userData.email })) {
      throw new UserWithThatEmailAlreadyExistsException(userData.email)
    }
    const hashedPassword = await bcrypt.hash(userData.password, 10)
    const user = await this.user.create({
      ...userData,
      password: hashedPassword,
    })
    const tokenData = this.createToken(user)
    const cookie = this.createCookie(tokenData)
    return {
      cookie,
      user,
    }
  }
  public createCookie(tokenData: TokenData) {
    return `Authorization=${tokenData.access_token}; HttpOnly; Max-Age=${tokenData.expire_at}`
  }
  public createToken(user: User): TokenData {
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

export default AuthenticationService
