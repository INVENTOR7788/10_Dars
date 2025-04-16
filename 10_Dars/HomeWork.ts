// 1_MAIN.TS

// import { NestFactory } from '@nestjs/core';
// import { AppModule } from './app.module';
// import { ValidationPipe } from '@nestjs/common';

// async function bootstrap() {
//   const app = await NestFactory.create(AppModule);
//   app.useGlobalPipes(
//     new ValidationPipe({
//       transform: true,
//       whitelist: true,
//       forbidNonWhitelisted: true,
//     }),
//   );

//   await app.listen(3000);
// }
// bootstrap();




// 2_MODULE.TS
// srd faylni ichida ochiladi 

// import { Module } from '@nestjs/common';
// import { APP_INTERCEPTOR, APP_GUARD } from '@nestjs/core';

// import { UsersModule } from './users/users.module';
// import { CoursesModule } from './courses/courses.module';
// import { AuthModule } from './auth/auth.module';

// import { TransformInterceptor } from './common/interceptors/transform.interceptor';
// import { ThrottlerGuard } from './common/guards/throttler.guard';

// @Module({
//   imports: [UsersModule, CoursesModule, AuthModule],
//   providers: [
//     {
//       provide: APP_INTERCEPTOR,
//       useClass: TransformInterceptor,
//     },
//     {
//       provide: APP_GUARD,
//       useClass: ThrottlerGuard,
//     },
//   ],
// })
// export class AppModule {}



// 3_Interceptorlar_ logging.interceptor.ts, transform.interceptor.ts, timeout.interceptor.ts

// import {
//     Injectable,
//     NestInterceptor,
//     ExecutionContext,
//     CallHandler,
//     Logger,
//   } from '@nestjs/common';
//   import { Observable, tap } from 'rxjs';
  
//   @Injectable()
//   export class LoggingInterceptor implements NestInterceptor {
//     private readonly logger = new Logger('HTTP');
  
//     intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
//       const request = context.switchToHttp().getRequest();
//       const { method, url, ip } = request;
//       const now = Date.now();
  
//       return next.handle().pipe(
//         tap(() => {
//           const delay = Date.now() - now;
//           this.logger.log(`${method} ${url} (${ip}) ${delay}ms`);
//         }),
//       );
//     }
//   }
  



// 3TransformInterceptor

// import {
//     Injectable,
//     NestInterceptor,
//     ExecutionContext,
//     CallHandler,
//   } from '@nestjs/common';
//   import { map, Observable } from 'rxjs';
  
//   @Injectable()
//   export class TransformInterceptor<T> implements NestInterceptor<T, any> {
//     intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
//       return next.handle().pipe(
//         map((data) => {
//           return {
//             data,
//             count: Array.isArray(data) ? data.length : undefined,
//           };
//         }),
//       );
//     }
//   }
  

// 3TimeoutInterceptor
// import {
//   Injectable,
//   NestInterceptor,
//   ExecutionContext,
//   CallHandler,
//   RequestTimeoutException,
// } from '@nestjs/common';
// import { Observable, TimeoutError, catchError, timeout } from 'rxjs';

// @Injectable()
// export class TimeoutInterceptor implements NestInterceptor {
//   intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
//     return next.handle().pipe(
//       timeout(5000),
//       catchError((err) => {
//         if (err instanceof TimeoutError) {
//           throw new RequestTimeoutException();
//         }
//         throw err;
//       }),
//     );
//   }
// }





// 4_Guardlar _auth.guard.ts, roles.guard.ts, throttler.guard.ts

// /auth.guard.ts

// import {
//     CanActivate,
//     ExecutionContext,
//     Injectable,
//     UnauthorizedException,
//   } from '@nestjs/common';
//   import * as jwt from 'jsonwebtoken';
  
//   @Injectable()
//   export class AuthGuard implements CanActivate {
//     canActivate(context: ExecutionContext): boolean {
//       const request = context.switchToHttp().getRequest();
//       const authHeader = request.headers.authorization;
  
//       if (!authHeader || !authHeader.startsWith('Bearer ')) {
//         throw new UnauthorizedException('Token mavjud emas');
//       }
  
//       const token = authHeader.split(' ')[1];
//       try {
//         const decoded = jwt.verify(token, 'JWT_SECRET_KEY');
//         request.user = decoded;
//         return true;
//       } catch (e) {
//         throw new UnauthorizedException('Token noto‘g‘ri yoki muddati o‘tgan');
//       }
//     }
//   }
  

// /roles.guard.ts

// import {
//     CanActivate,
//     ExecutionContext,
//     ForbiddenException,
//     Injectable,
//   } from '@nestjs/common';
//   import { Reflector } from '@nestjs/core';
  
//   @Injectable()
//   export class RolesGuard implements CanActivate {
//     constructor(private reflector: Reflector) {}
  
//     canActivate(context: ExecutionContext): boolean {
//       const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
//         context.getHandler(),
//         context.getClass(),
//       ]);
//       if (!requiredRoles) return true;
  
//       const request = context.switchToHttp().getRequest();
//       const user = request.user;
//       if (!user || !requiredRoles.includes(user.role)) {
//         throw new ForbiddenException('Sizda ruxsat yo‘q');
//       }
  
//       return true;
//     }
//   }
  

// /roles.decorator.ts
// import { SetMetadata } from '@nestjs/common';

// export const Roles = (...roles: string[]) => SetMetadata('roles', roles);


// /throttler.guard.ts
// import { ThrottlerGuard as BaseThrottlerGuard } from '@nestjs/throttler';
// import { Injectable } from '@nestjs/common';

// @Injectable()
// export class ThrottlerGuard extends BaseThrottlerGuard {}



// 5_ Validatorlar

// /create-user.dto.ts

// import {
//     IsEmail,
//     IsIn,
//     IsNotEmpty,
//     IsString,
//     Matches,
//     MinLength,
//   } from 'class-validator';
  
//   export class CreateUserDto {
//     @IsNotEmpty()
//     @IsString()
//     fullName: string;
  
//     @IsEmail()
//     email: string;
  
//     @IsString()
//     @MinLength(8)
//     @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/, {
//       message: 'Parolda harf va raqam bo‘lishi shart',
//     })
//     password: string;
  
//     @IsIn(['student', 'teacher', 'admin'])
//     role: string;
//   }
  

// /create-course.dto.ts

// import { IsNotEmpty, IsNumber, IsString, Min, MinLength } from 'class-validator';

// export class CreateCourseDto {
//   @IsNotEmpty()
//   @IsString()
//   @MinLength(5)
//   title: string;

//   @IsNotEmpty()
//   @IsString()
//   description: string;

//   @IsNumber()
//   @Min(0)
//   price: number;

//   @IsString()
//   duration: string;
// }

