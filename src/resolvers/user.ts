import { User } from "../entities/User";
import { MyContext } from "src/types";
import { Arg, Ctx, Field, InputType, Mutation, ObjectType, Query, Resolver } from "type-graphql";
import argon2 from 'argon2'; 

@InputType()
class UserInputUsernamePass {
    @Field()
    username: string;

    @Field()
    password: string;
}

@ObjectType()
class FieldError {
    @Field()
    field: string;

    @Field()
    message: string;
}
 

@ObjectType()
class UserResponse {
    @Field(() => [FieldError], {nullable: true})
    errors?: FieldError[];

    @Field(() => User, {nullable: true})
    user?: User
}



@Resolver()
export class UserResolver {
    @Query(() => User, {nullable: true})
    async me(
        @Ctx() ctx: MyContext
    ) {
        if(!ctx.req.session!.userId ) {
            return null;
        }

        const user = await ctx.em.findOne(User, {id: ctx.req.session!.userId});
        return user;
    }

    @Mutation(() => UserResponse)
    async registerUser(
        @Arg("options") options: UserInputUsernamePass,
        @Ctx() ctx: MyContext
    ): Promise<UserResponse> {
        if(options.username.length <= 2) { 
            return { 
                errors: [{
                    field: "username",
                    message: "Username length must be greater than 2"
                }]
            }
        }

        if(options.password.length <= 2) {
            return {
                errors: [{
                    field: "password",
                    message: "Password length must be greater than 2"
                }]
            }
        } 

        const hashedPwd = await argon2.hash(options.password);
        const user = ctx.em.create(User, {username: options.username, password: hashedPwd});

        try {
            await ctx.em.persistAndFlush(user);
        } catch(err) {
            console.log(err);
            if(err.code === "23505") {
                return {
                    errors: [{
                        field: "username",
                        message: "user already exists"
                    }]
                }
            } 
        }

        return {
            user
        };
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg("options") options: UserInputUsernamePass,
        @Ctx() ctx: MyContext
    ): Promise<UserResponse> {
        const user = await ctx.em.findOne(User, {username: options.username});
        if(!user) {
            return {
                errors: [{
                    field: "username",
                    message: "username doesn't exists"
                }]
            };
        }

        const valid = await argon2.verify(user.password, options.password);
        if(!valid) {
            return {
                errors: [{
                    field: "password",
                    message: "invalid password"
                }]
            };
        }

        ctx.req.session!.userId = user.id; 

        return {
            user,
        }
    }

}