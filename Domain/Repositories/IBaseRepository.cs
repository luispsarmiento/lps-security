using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Repositories
{
    public interface IBaseRepository<T> where T : class
    {
        Task<T> Add(T entity);
        Task<IEnumerable<T>> Find(Expression<Func<T, bool>> predicate);
        Task<T> Update(T entity);
        Task Delete(T entity);
    }
}
