import {
  formatJSONResponse,
  ValidatedEventAPIGatewayProxyEvent,
} from "@libs/api-gateway";
import { middyfy } from "@libs/lambda";
import { v4 as uuidV4 } from "uuid";
import schema from "@functions/volunteers/createVolunteer/CreateVolunteerSchema";
import { dynamo } from "../../../database/DynamoDBClient";
import { BaseException } from "../../../utils/BaseException";
import { errorHandler } from "../../../utils/ErrorHandler";

const createVolunteerHandler: ValidatedEventAPIGatewayProxyEvent<
  typeof schema
> = async (event) => {
  const { phoneNumber, fullName, email } = event.body;

  const volunteerExists = await dynamo
    .query({
      TableName: "volunteers",
      IndexName: "email_index",
      KeyConditionExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": email,
      },
    })
    .promise();

  if (volunteerExists.Count > 0) {
    throw new BaseException("VolunteerExists", "Volunteer already exists!");
  }

  const volunteerItem = {
    id: uuidV4(),
    email,
    fullName,
    phoneNumber,
  };

  await dynamo
    .put({
      TableName: "volunteers",
      Item: volunteerItem,
    })
    .promise();

  return formatJSONResponse(201, volunteerItem);
};

export const handle = middyfy(createVolunteerHandler).onError(errorHandler);
