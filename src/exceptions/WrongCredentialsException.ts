import HttpException from './HttpException'

class WrongCredentialsException extends HttpException {
  constructor() {
    super(401, 'Unauthorized')
  }
}

export default WrongCredentialsException
