import { middyfy } from "../../../../utils/Lambda";
import {
  formatJSONResponse,
  ValidatedEventAPIGatewayProxyEvent,
} from "../../../../utils/ApiGateway";
import loginAdminSchema from "@auth/handlers/loginAdmin/LoginAdminSchema";
import { errorHandler } from "../../../../utils/ErrorHandler";
import { BaseException } from "../../../../utils/BaseException";
import { compare } from "bcryptjs";
import { sign } from "jsonwebtoken";
import { diContainer } from "src/shared/container";
import { IAdminsRepository } from "src/modules/admins/repositories/IAdminsRepository";
import { AdminMapper } from "@volunteers/mappers/AdminMapper";

const loginAdminHandler: ValidatedEventAPIGatewayProxyEvent<
  typeof loginAdminSchema
> = async (event) => {
  const repository = diContainer.resolve<IAdminsRepository>(
    "OneTableAdminsRepository"
  );

  const { password, email } = event.body;

  const adminExists = await repository.findByEmail(email);

  if (!adminExists) {
    throw new BaseException(
      "EmailOrPasswordInvalid",
      "The email or password is invalid!",
      401
    );
  }

  const passwordMatch = await compare(password, adminExists.password);

  if (!passwordMatch) {
    throw new BaseException(
      "EmailOrPasswordInvalid",
      "The email or password is invalid!",
      401
    );
  }

  const token = sign({ email: adminExists.email }, process.env.JWT_SECRET, {
    subject: adminExists.id,
  });

  return formatJSONResponse(200, {
    token,
    user: AdminMapper.toMapper(adminExists),
  });
};

export const handle = middyfy(loginAdminHandler).onError(errorHandler);
